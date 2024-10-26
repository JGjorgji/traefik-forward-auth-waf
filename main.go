package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"

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
}

type Rule struct {
	Name     string `yaml:"name"`
	Priority int    `yaml:"priority"`
	Rule     string `yaml:"rule"`
	Action   string `yaml:"action"`
}

type ServerConfig struct {
	Port   int    `yaml:"port"`
	Host   string `yaml:"host"`
	DbPath string `yaml:"dbPath"`
}

type Config struct {
	Rules  []Rule       `yaml:"rules"`
	Server ServerConfig `yaml:"server"`
}

func (s *Server) getCountryByIP(ip net.IP) (string, error) {
	if ip == nil {
		return "", fmt.Errorf("invalid IP address")
	}

	record, err := s.db.Country(ip)
	if err != nil {
		return "", fmt.Errorf("failed to get country information: %w", err)
	}

	return record.Country.IsoCode, nil
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	method := r.Header.Get("X-Forwarded-Method")
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	forwardedFor := r.Header.Get("X-Forwarded-For")
	customAuthHeader := r.Header.Get("X-Custom-Auth")

	uuid := uuid.New().String()

	ip := net.ParseIP(forwardedFor)
	if ip == nil {
		http.Error(w, "Invalid IP address", http.StatusUnauthorized)
		return
	}

	record, err := s.getCountryByIP(ip)
	if err != nil {
		http.Error(w, uuid, http.StatusForbidden)
		fmt.Println("Failed to get country information")
		s.logger.Info("Failed to get country information", zap.String("action", "undefined"),
			zap.String("uuid", uuid),
			zap.String("method", method),
			zap.String("proto", proto),
			zap.String("host", host),
			zap.String("uri", uri),
			zap.String("ip", forwardedFor),
			zap.String("rule", "undefined"))
		return
	}

	ctx := NewContext()
	ctx.Variables["method"] = method
	ctx.Variables["proto"] = proto
	ctx.Variables["host"] = host
	ctx.Variables["uri"] = uri
	ctx.Variables["ip"] = forwardedFor
	ctx.Variables["country"] = record
	ctx.Variables["authheader"] = customAuthHeader

	for i := range s.rules {
		result, err := s.parsedRules[i].Evaluate(ctx)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
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
					zap.String("ip", forwardedFor),
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
					zap.String("ip", forwardedFor),
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
					zap.String("ip", forwardedFor),
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
				zap.String("ip", forwardedFor),
				zap.String("rule", s.rules[i].Name))
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", strconv.Itoa(0))
}

func main() {
	// zap used for the high performance logging
	logger, _ := zap.NewProduction()
	defer logger.Sync()

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

	server := &Server{db: db, rules: cfg.Rules, parsedRules: parsedRules, logger: logger}

	http.HandleFunc("/", server.handler)

	fmt.Fprintf(os.Stdout, "Starting server on %v:%v\n", cfg.Server.Host, cfg.Server.Port)
	if err := http.ListenAndServe(fmt.Sprintf("%v:%v", cfg.Server.Host, cfg.Server.Port), nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
