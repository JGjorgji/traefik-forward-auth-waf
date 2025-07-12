package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/oschwald/geoip2-golang"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type Server struct {
	db          *geoip2.Reader
	rules       []Rule
	parsedRules []ExpressionEvaluator
	logger      *zap.Logger
	config      *Config
}

type Rule struct {
	Name     string `yaml:"name"`
	Priority int    `yaml:"priority"`
	Rule     string `yaml:"rule"`
	Action   string `yaml:"action"`
}

type ServerConfig struct {
	Port         int    `yaml:"port"`
	Host         string `yaml:"host"`
	DbPath       string `yaml:"dbPath"`
	RequireGeoIP bool   `yaml:"requireGeoIP"` // Default false - make GeoIP optional
	LogLevel     string `yaml:"logLevel"`     // debug, info, warn, error
}

type Config struct {
	Rules  []Rule       `yaml:"rules"`
	Server ServerConfig `yaml:"server"`
}

func (s *Server) getCountryByIP(ip net.IP) (string, error) {
	record, err := s.db.Country(ip)
	if err != nil {
		return "", fmt.Errorf("failed to get country information: %w", err)
	}

	return record.Country.IsoCode, nil
}

func (s *Server) getContinentByIP(ip net.IP) (string, error) {
	record, err := s.db.Country(ip)
	if err != nil {
		return "", fmt.Errorf("failed to get continent information: %w", err)
	}

	return record.Continent.Code, nil
}

func (s *Server) getAsnByIP(ip net.IP) (string, error) {
	record, err := s.db.ASN(ip)
	if err != nil {
		// ASN data might not be available in Country database
		return "0", nil // Return default value instead of error
	}

	return strconv.Itoa(int(record.AutonomousSystemNumber)), nil
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	method := r.Header.Get("X-Forwarded-Method")
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	forwardedFor := r.Header.Get("X-Forwarded-For")
	customAuthHeader := r.Header.Get("X-Custom-Auth")
	userAgent := r.Header.Get("User-Agent")

	uuid := uuid.New().String()

	// Handle X-Forwarded-For which might contain multiple IPs (comma-separated)
	// Take the first IP which should be the original client IP
	var clientIP string
	if forwardedFor == "" {
		s.logger.Error("X-Forwarded-For header is missing", zap.String("remote_addr", r.RemoteAddr))
		http.Error(w, "X-Forwarded-For header required", http.StatusBadRequest)
		return
	}

	ips := strings.Split(forwardedFor, ",")
	clientIP = strings.TrimSpace(ips[0])

	ip := net.ParseIP(clientIP)
	if ip == nil {
		s.logger.Error("Invalid IP address in X-Forwarded-For", zap.String("ip", clientIP), zap.String("forwarded_for", forwardedFor))
		http.Error(w, "Invalid IP address in X-Forwarded-For", http.StatusBadRequest)
		return
	}

	country, err_country := s.getCountryByIP(ip)
	continent, err_continent := s.getContinentByIP(ip)
	asnum, err_asnum := s.getAsnByIP(ip)

	// Log specific errors but only fail if critical lookups fail
	if err_country != nil {
		s.logger.Error("Failed to get country data", zap.Error(err_country), zap.String("ip", forwardedFor))
	}
	if err_continent != nil {
		s.logger.Error("Failed to get continent data", zap.Error(err_continent), zap.String("ip", forwardedFor))
	}
	if err_asnum != nil {
		s.logger.Warn("Failed to get ASN data (this may be normal if using Country DB)", zap.Error(err_asnum), zap.String("ip", forwardedFor))
	}

	// Only fail on critical errors if GeoIP is required
	if s.config.Server.RequireGeoIP && (err_country != nil || err_continent != nil) {
		http.Error(w, uuid, http.StatusForbidden)
		s.logger.Info("Failed to get critical GeoIP data, denying request as a fail safe.",
			zap.String("action", "undefined"),
			zap.String("uuid", uuid),
			zap.String("method", method),
			zap.String("proto", proto),
			zap.String("host", host),
			zap.String("uri", uri),
			zap.String("ip", clientIP),
			zap.String("rule", "undefined"),
			zap.Error(err_country),
			zap.Error(err_continent))
		return
	}

	// Use default values if GeoIP lookup fails and it's not required
	if country == "" {
		country = "XX" // Unknown country code
	}
	if continent == "" {
		continent = "XX" // Unknown continent code
	}

	ctx := NewContext()
	ctx.Variables[HttpRequestMethod] = method
	ctx.Variables[Proto] = proto
	ctx.Variables[HttpHost] = host
	ctx.Variables[HttpRequestUri] = uri
	ctx.Variables[IpSrc] = clientIP
	ctx.Variables[IpGeoipCountry] = country
	ctx.Variables[AuthHeader] = customAuthHeader
	ctx.Variables[UserAgent] = userAgent
	ctx.Variables[IpGeopipContinent] = continent
	ctx.Variables[IpGeoipAsNum] = asnum

	// Populate headers for header-based rules
	for headerName, headerValues := range r.Header {
		ctx.Headers[headerName] = headerValues
	}

	for i := range s.rules {
		result, err := s.parsedRules[i].Evaluate(ctx)
		if err != nil {
			s.logger.Error("Rule evaluation error", zap.Error(err), zap.String("rule", s.rules[i].Name), zap.String("uuid", uuid))
			http.Error(w, uuid, http.StatusForbidden)
			return
		}
		// expression evaluated to true, process the action
		if result {
			switch s.rules[i].Action {
			case "skip":
				w.WriteHeader(http.StatusOK)
				s.logger.Info("Allowed request", zap.String("action", s.rules[i].Action),
					zap.String("uuid", uuid),
					zap.String("method", method),
					zap.String("proto", proto),
					zap.String("host", host),
					zap.String("uri", uri),
					zap.String("ip", clientIP),
					zap.String("rule", s.rules[i].Name))
				return
			case "block":
				http.Error(w, uuid, http.StatusForbidden)
				w.Header().Set("Content-Type", strconv.Itoa(37))
				s.logger.Info("Blocked request", zap.String("action", s.rules[i].Action),
					zap.String("uuid", uuid),
					zap.String("method", method),
					zap.String("proto", proto),
					zap.String("host", host),
					zap.String("uri", uri),
					zap.String("ip", clientIP),
					zap.String("rule", s.rules[i].Name))
				return
			default:
				http.Error(w, uuid, http.StatusForbidden)
				w.Header().Set("Content-Type", strconv.Itoa(37))
				s.logger.Info("Blocked request because no action was provided", zap.String("action", s.rules[i].Action),
					zap.String("uuid", uuid),
					zap.String("method", method),
					zap.String("proto", proto),
					zap.String("host", host),
					zap.String("uri", uri),
					zap.String("ip", clientIP),
					zap.String("rule", s.rules[i].Name))
				return
			}
		} else {
			s.logger.Debug("Request doesn't match any rule", zap.String("action", s.rules[i].Action),
				zap.String("uuid", uuid),
				zap.String("method", method),
				zap.String("proto", proto),
				zap.String("host", host),
				zap.String("uri", uri),
				zap.String("ip", clientIP),
				zap.String("rule", s.rules[i].Name))
		}
	}

	// No rules matched, allow the request by default
	s.logger.Info("No rules matched, allowing request",
		zap.String("uuid", uuid),
		zap.String("method", method),
		zap.String("proto", proto),
		zap.String("host", host),
		zap.String("uri", uri),
		zap.String("ip", clientIP))

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", strconv.Itoa(0))
}

func main() {
	uuid.EnableRandPool()

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		log.Fatalf("Failed to unmarshal YAML: %v", err)
	}

	// Configure zap logger with the log level from config
	config := zap.NewProductionConfig()

	// Set log level based on config
	switch strings.ToLower(cfg.Server.LogLevel) {
	case "debug":
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		config.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		config.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel) // Default to info if not specified
	}

	logger, err := config.Build()
	if err != nil {
		log.Fatalf("Failed to build logger: %v", err)
	}
	defer logger.Sync()

	sort.Slice(cfg.Rules, func(i, j int) bool {
		return cfg.Rules[i].Priority < cfg.Rules[j].Priority
	})

	var parsedRules []ExpressionEvaluator

	for _, rule := range cfg.Rules {
		evaluator, err := NewExpressionEvaluator(rule.Rule)
		if err != nil {
			log.Fatalf("Failed to parse rule: %v", err)
		}
		parsedRules = append(parsedRules, *evaluator)
	}

	db, err := geoip2.Open(cfg.Server.DbPath)
	if err != nil {
		log.Fatalf("Failed to open GeoIP database: %v", err)
	}
	defer db.Close()

	server := &Server{db: db, rules: cfg.Rules, parsedRules: parsedRules, logger: logger, config: &cfg}

	http.HandleFunc("/", server.handler)

	fmt.Fprintf(os.Stdout, "Starting server on %v:%v\n", cfg.Server.Host, cfg.Server.Port)
	if err := http.ListenAndServe(fmt.Sprintf("%v:%v", cfg.Server.Host, cfg.Server.Port), nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
