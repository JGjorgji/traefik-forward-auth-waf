package main

import (
	"testing"
)

func TestLexer(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []Token
		wantErr  bool
	}{
		{
			name:  "simple equality",
			input: `http.host eq "example.com"`,
			expected: []Token{
				{Type: TOKEN_FIELD, Value: "http.host", Position: 0},
				{Type: TOKEN_COMPARISON, Value: "eq", Position: 4},
				{Type: TOKEN_STRING, Value: "example.com", Position: 8},
				{Type: TOKEN_EOF, Value: "", Position: 19},
			},
			wantErr: false,
		},
		{
			name:  "compound expression with parentheses",
			input: `(http.request.uri eq "*.jpg") and (ip.geoip.country in {"US" "MK"})`,
			expected: []Token{
				{Type: TOKEN_LPAREN, Value: "(", Position: 0},
				{Type: TOKEN_FIELD, Value: "http.request.uri", Position: 1},
				{Type: TOKEN_COMPARISON, Value: "eq", Position: 5},
				{Type: TOKEN_STRING, Value: "*.jpg", Position: 9},
				{Type: TOKEN_RPAREN, Value: ")", Position: 15},
				{Type: TOKEN_LOGICAL_OP, Value: "and", Position: 17},
				{Type: TOKEN_LPAREN, Value: "(", Position: 21},
				{Type: TOKEN_FIELD, Value: "ip.geoip.country", Position: 22},
				{Type: TOKEN_SET_COMPARISON, Value: "in", Position: 30},
				{Type: TOKEN_LCURLY, Value: "{", Position: 33},
				{Type: TOKEN_STRING, Value: "US", Position: 34},
				{Type: TOKEN_STRING, Value: "MK", Position: 38},
				{Type: TOKEN_RCURLY, Value: "}", Position: 41},
				{Type: TOKEN_RPAREN, Value: ")", Position: 42},
				{Type: TOKEN_EOF, Value: "", Position: 43},
			},
			wantErr: false,
		},
		{
			name:    "invalid token",
			input:   "http.host @ example.com",
			wantErr: true,
		},
		{
			name:    "unterminated string",
			input:   `http.host eq "example.com`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lexer := NewLexer(tt.input)
			tokens, err := lexer.Tokenize()

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(tokens) != len(tt.expected) {
				t.Errorf("token count mismatch\nwant: %d\ngot:  %d", len(tt.expected), len(tokens))
				return
			}

			for i, token := range tokens {
				expectedToken := tt.expected[i]
				if token.Type != expectedToken.Type || token.Value != expectedToken.Value {
					t.Errorf("token %d mismatch\nwant: {Type:%d Value:%q Position:%d}\ngot:  {Type:%d Value:%q Position:%d}",
						i, expectedToken.Type, expectedToken.Value, expectedToken.Position,
						token.Type, token.Value, token.Position)
				}
			}
		})
	}
}

func TestParser(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Node
		wantErr  bool
	}{
		{
			name:  "simple equality",
			input: `http.host eq "example.com"`,
			expected: Node{
				Type: NODE_EXPRESSION,
				Children: []Node{
					{
						Type:  NODE_STATEMENT,
						Value: "http.host eq",
						Children: []Node{
							{Type: NODE_EXPRESSION, Value: "example.com"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:  "simple in set",
			input: `ip.geoip.country in {"US" "MK"}`,
			expected: Node{
				Type: NODE_EXPRESSION,
				Children: []Node{
					{
						Type:  NODE_STATEMENT,
						Value: "ip.geoip.country in",
						Children: []Node{
							{
								Type:  NODE_EXPRESSION,
								Value: "set",
								Children: []Node{
									{Type: NODE_EXPRESSION, Value: "US"},
									{Type: NODE_EXPRESSION, Value: "MK"},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid syntax",
			input:   "http.host eq",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lexer := NewLexer(tt.input)
			tokens, err := lexer.Tokenize()
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("lexer error: %v", err)
				}
				return
			}

			parser := NewParser(tokens)
			ast, err := parser.Parse()

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			compareNodes(t, "", tt.expected, ast)
		})
	}
}

// Helper function to compare AST nodes
func compareNodes(t *testing.T, path string, expected, got Node) {
	if expected.Type != got.Type {
		t.Errorf("%s: node type mismatch\nwant: %v\ngot:  %v", path, expected.Type, got.Type)
	}
	if expected.Value != got.Value {
		t.Errorf("%s: node value mismatch\nwant: %v\ngot:  %v", path, expected.Value, got.Value)
	}
	if expected.Negated != got.Negated {
		t.Errorf("%s: node negated mismatch\nwant: %v\ngot:  %v", path, expected.Negated, got.Negated)
	}
	if len(expected.Children) != len(got.Children) {
		t.Errorf("%s: children count mismatch\nwant: %d\ngot:  %d", path, len(expected.Children), len(got.Children))
		return
	}
	for i := range expected.Children {
		childPath := path + "/" + expected.Children[i].Value
		compareNodes(t, childPath, expected.Children[i], got.Children[i])
	}
}

func TestEvaluator(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		context    map[string]string
		expected   bool
		wantErr    bool
	}{
		{
			name:       "simple equality match",
			expression: `http.host eq "example.com"`,
			context: map[string]string{
				"http.host": "example.com",
			},
			expected: true,
			wantErr:  false,
		},
		{
			name:       "simple equality non-match",
			expression: `http.host eq "example.com"`,
			context: map[string]string{
				"http.host": "other.com",
			},
			expected: false,
			wantErr:  false,
		},
		{
			name:       "compound AND expression",
			expression: `(http.host eq "example.com") and (ip.geoip.country eq "US")`,
			context: map[string]string{
				"http.host":        "example.com",
				"ip.geoip.country": "US",
			},
			expected: true,
			wantErr:  false,
		},
		{
			name:       "compound OR expression",
			expression: `(http.host eq "example.com") or (ip.geoip.country eq "US")`,
			context: map[string]string{
				"http.host":        "other.com",
				"ip.geoip.country": "US",
			},
			expected: true,
			wantErr:  false,
		},
		{
			name:       "negated in set",
			expression: `not ip.geoip.country in {"US" "CA"}`,
			context: map[string]string{
				"ip.geoip.country": "UK",
			},
			expected: true,
			wantErr:  false,
		},
		{
			name:       "IP in CIDR",
			expression: `ip.src in {"192.168.0.0/24"}`,
			context: map[string]string{
				"ip.src": "192.168.0.1",
			},
			expected: true,
			wantErr:  false,
		},
		{
			name:       "IP not in CIDR",
			expression: `ip.src in {"192.168.0.0/24"}`,
			context: map[string]string{
				"ip.src": "192.169.0.1",
			},
			expected: false,
			wantErr:  false,
		},
		{
			name:       "wildcard match",
			expression: `http.request.uri wildcard "/*.jpg"`,
			context: map[string]string{
				"http.request.uri": "/image.jpg",
			},
			expected: true,
			wantErr:  false,
		},
		{
			name:       "missing variable",
			expression: `http.host eq "example.com"`,
			context:    map[string]string{},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator, err := NewExpressionEvaluator(tt.expression)
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("failed to create evaluator: %v", err)
				}
				return
			}

			ctx := NewContext()
			ctx.Variables = tt.context

			result, err := evaluator.Evaluate(ctx)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("evaluation result mismatch\nwant: %v\ngot:  %v", tt.expected, result)
			}
		})
	}
}

func TestCustomEvaluatorFunctions(t *testing.T) {
	evaluator, err := NewExpressionEvaluator(`http.host eq "CUSTOM"`)
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	customCalled := false
	evaluator.SetEqualityFn(func(value string, target string) bool {
		customCalled = true
		return value == "custom" && target == "CUSTOM"
	})

	ctx := NewContext()
	ctx.Variables = map[string]string{
		"http.host": "custom",
	}

	result, err := evaluator.Evaluate(ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if !customCalled {
		t.Error("custom equality function was not called")
	}

	if !result {
		t.Error("custom equality function returned unexpected result")
	}
}

func TestIPSetFunction(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		targets  []string
		expected bool
	}{
		{
			name:     "IP in CIDR",
			ip:       "192.168.1.1",
			targets:  []string{"192.168.1.0/24"},
			expected: true,
		},
		{
			name:     "IP not in CIDR",
			ip:       "192.168.2.1",
			targets:  []string{"192.168.1.0/24"},
			expected: false,
		},
		{
			name:     "IP equals exact IP",
			ip:       "192.168.1.1",
			targets:  []string{"192.168.1.1"},
			expected: true,
		},
		{
			name:     "Invalid IP",
			ip:       "invalid-ip",
			targets:  []string{"192.168.1.0/24"},
			expected: false,
		},
		{
			name:     "Invalid CIDR",
			ip:       "192.168.1.1",
			targets:  []string{"invalid-cidr"},
			expected: false,
		},
	}

	evaluator := NewEvaluator()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluator.InIpSetFn(tt.ip, tt.targets)
			if result != tt.expected {
				t.Errorf("InIpSetFn result mismatch\nwant: %v\ngot:  %v", tt.expected, result)
			}
		})
	}
}

func TestWildcardFunction(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		pattern  string
		expected bool
	}{
		{
			name:     "exact match",
			value:    "example.jpg",
			pattern:  "example.jpg",
			expected: true,
		},
		{
			name:     "wildcard suffix match",
			value:    "image.jpg",
			pattern:  "*.jpg",
			expected: true,
		},
		{
			name:     "wildcard prefix match",
			value:    "prefix-name",
			pattern:  "prefix-*",
			expected: true,
		},
		{
			name:     "no match",
			value:    "example.png",
			pattern:  "*.jpg",
			expected: false,
		},
		{
			name:     "invalid pattern",
			value:    "example.jpg",
			pattern:  "[invalid",
			expected: false,
		},
	}

	evaluator := NewEvaluator()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluator.WildCardFn(tt.value, tt.pattern)
			if result != tt.expected {
				t.Errorf("WildCardFn result mismatch\nwant: %v\ngot:  %v", tt.expected, result)
			}
		})
	}
}
