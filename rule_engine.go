package main

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"unicode"
)

// TokenType represents different types of tokens in our grammar
type TokenType int

const (
	TOKEN_LPAREN TokenType = iota
	TOKEN_RPAREN
	TOKEN_NOT
	TOKEN_FIELD
	TOKEN_COMPARISON
	TOKEN_STRING
	TOKEN_NUMBER
	TOKEN_LBRACKET
	TOKEN_RBRACKET
	TOKEN_COMMA
	TOKEN_LOGICAL_OP
	TOKEN_EOF
)

// Token represents a lexical token
type Token struct {
	Type     TokenType
	Value    string
	Position int
}

// Lexer breaks input into tokens
type Lexer struct {
	input    string
	position int
	tokens   []Token
}

// Parser represents our parser state
type Parser struct {
	tokens   []Token
	position int
}

// AST Node types
type NodeType int

const (
	NODE_EXPRESSION NodeType = iota
	NODE_STATEMENT
	NODE_COMPOUND
)

// Node represents an AST node
type Node struct {
	Type     NodeType
	Value    string
	Negated  bool
	Children []Node
}

// NewLexer creates a new lexer instance
func NewLexer(input string) *Lexer {
	return &Lexer{
		input:    input,
		position: 0,
		tokens:   make([]Token, 0),
	}
}

// Tokenize converts input string into tokens
func (l *Lexer) Tokenize() ([]Token, error) {
	for l.position < len(l.input) {
		char := l.current()

		switch {
		case char == '(':
			l.addToken(TOKEN_LPAREN, "(")
			l.advance()
		case char == ')':
			l.addToken(TOKEN_RPAREN, ")")
			l.advance()
		case char == '[':
			l.addToken(TOKEN_LBRACKET, "[")
			l.advance()
		case char == ']':
			l.addToken(TOKEN_RBRACKET, "]")
			l.advance()
		case char == ',':
			l.addToken(TOKEN_COMMA, ",")
			l.advance()
		case char == '\'':
			token, err := l.readString()
			if err != nil {
				return nil, err
			}
			l.addToken(TOKEN_STRING, token)
		case unicode.IsSpace(char):
			l.advance()
		case unicode.IsLetter(char):
			word := l.readWord()
			switch word {
			case "not":
				l.addToken(TOKEN_NOT, word)
			case "uri", "host", "ip", "country":
				l.addToken(TOKEN_FIELD, word)
			case "eq", "ne", "in", "wildcard":
				l.addToken(TOKEN_COMPARISON, word)
			case "and", "or":
				l.addToken(TOKEN_LOGICAL_OP, word)
			default:
				return nil, fmt.Errorf("unexpected word: %s", word)
			}
		default:
			return nil, fmt.Errorf("unexpected character: %c", char)
		}
	}

	l.addToken(TOKEN_EOF, "")
	return l.tokens, nil
}

func (l *Lexer) current() rune {
	if l.position >= len(l.input) {
		return 0
	}
	return rune(l.input[l.position])
}

func (l *Lexer) advance() {
	l.position++
}

func (l *Lexer) addToken(tokenType TokenType, value string) {
	l.tokens = append(l.tokens, Token{Type: tokenType, Value: value, Position: l.position})
}

func (l *Lexer) readString() (string, error) {
	l.advance() // Skip opening quote
	start := l.position
	for l.position < len(l.input) && l.current() != '\'' {
		l.advance()
	}
	if l.position >= len(l.input) {
		return "", errors.New("unterminated string")
	}
	value := l.input[start:l.position]
	l.advance() // Skip closing quote
	return value, nil
}

func (l *Lexer) readWord() string {
	start := l.position
	for l.position < len(l.input) && (unicode.IsLetter(l.current()) || unicode.IsDigit(l.current())) {
		l.advance()
	}
	return l.input[start:l.position]
}

// NewParser creates a new parser instance
func NewParser(tokens []Token) *Parser {
	return &Parser{
		tokens:   tokens,
		position: 0,
	}
}

// Parse parses the tokens into an AST
func (p *Parser) Parse() (Node, error) {
	return p.parseCompound()
}

func (p *Parser) parseCompound() (Node, error) {
	expr, err := p.parseExpression()
	if err != nil {
		return Node{}, err
	}

	nodes := []Node{expr}

	for p.position < len(p.tokens)-1 && p.current().Type == TOKEN_LOGICAL_OP {
		op := p.current().Value
		p.advance()

		right, err := p.parseExpression()
		if err != nil {
			return Node{}, err
		}

		nodes = append(nodes, Node{Type: NODE_EXPRESSION, Value: op})
		nodes = append(nodes, right)
	}

	if len(nodes) == 1 {
		return nodes[0], nil
	}

	return Node{
		Type:     NODE_COMPOUND,
		Children: nodes,
	}, nil
}

func (p *Parser) parseExpression() (Node, error) {
	if p.current().Type != TOKEN_LPAREN {
		return Node{}, errors.New("expected left parenthesis")
	}
	p.advance()

	// Check for negation inside parentheses
	innerNegated := false
	if p.current().Type == TOKEN_NOT {
		innerNegated = true
		p.advance()
	}

	stmt, err := p.parseStatement()
	if err != nil {
		return Node{}, err
	}

	// Update the statement's negation status
	stmt.Negated = innerNegated

	if p.current().Type != TOKEN_RPAREN {
		return Node{}, errors.New("expected right parenthesis")
	}
	p.advance()

	return Node{
		Type:     NODE_EXPRESSION,
		Children: []Node{stmt},
	}, nil
}

func (p *Parser) parseStatement() (Node, error) {
	if p.current().Type != TOKEN_FIELD {
		return Node{}, errors.New("expected field")
	}
	field := p.current().Value
	p.advance()

	if p.current().Type != TOKEN_COMPARISON {
		return Node{}, errors.New("expected comparison operator")
	}
	operator := p.current().Value
	p.advance()

	value, err := p.parseValue()
	if err != nil {
		return Node{}, err
	}

	return Node{
		Type:     NODE_STATEMENT,
		Value:    fmt.Sprintf("%s %s", field, operator),
		Children: []Node{value},
	}, nil
}

func (p *Parser) parseValue() (Node, error) {
	if p.current().Type == TOKEN_LBRACKET {
		return p.parseList()
	}
	if p.current().Type == TOKEN_STRING {
		value := p.current().Value
		p.advance()
		return Node{Type: NODE_EXPRESSION, Value: value}, nil
	}
	return Node{}, errors.New("expected value")
}

func (p *Parser) parseList() (Node, error) {
	if p.current().Type != TOKEN_LBRACKET {
		return Node{}, errors.New("expected left bracket")
	}
	p.advance()

	var items []Node
	for p.current().Type == TOKEN_STRING {
		items = append(items, Node{Type: NODE_EXPRESSION, Value: p.current().Value})
		p.advance()

		if p.current().Type == TOKEN_COMMA {
			p.advance()
		}
	}

	if p.current().Type != TOKEN_RBRACKET {
		return Node{}, errors.New("expected right bracket")
	}
	p.advance()

	return Node{
		Type:     NODE_EXPRESSION,
		Value:    "list",
		Children: items,
	}, nil
}

func (p *Parser) current() Token {
	if p.position >= len(p.tokens) {
		return Token{Type: TOKEN_EOF}
	}
	return p.tokens[p.position]
}

func (p *Parser) advance() {
	p.position++
}

// PrintAST prints the AST in a readable format
func PrintAST(node Node, indent string) {
	fmt.Printf("%sType: %v\n", indent, node.Type)
	if node.Value != "" {
		fmt.Printf("%sValue: %v\n", indent, node.Value)
	}
	if node.Negated {
		fmt.Printf("%sNegated: true\n", indent)
	}
	for _, child := range node.Children {
		PrintAST(child, indent+"  ")
	}
}

// Context holds the variable values for evaluation
type Context struct {
	Variables map[string]string
}

// NewContext creates a new evaluation context
func NewContext() *Context {
	return &Context{
		Variables: make(map[string]string),
	}
}

// Evaluator holds the functions for evaluating different operations
type Evaluator struct {
	// Function types for different operations
	EqualityFn    func(value string, target string) bool
	InFn          func(value string, targets []string) bool
	InIpFn        func(value string, targets []string) bool
	NotEqualityFn func(value string, target string) bool
	WildCardFn    func(value string, target string) bool
}

// NewEvaluator creates a new evaluator with custom functions
func NewEvaluator() *Evaluator {
	return &Evaluator{
		// Default implementations that can be overridden
		EqualityFn: func(value string, target string) bool {
			return value == target
		},
		InFn: func(value string, targets []string) bool {
			for _, t := range targets {
				if value == t {
					return true
				}
			}
			return false
		},
		InIpFn: func(value string, targets []string) bool {
			valueIp := net.ParseIP(value)
			for _, t := range targets {
				_, subnet, err := net.ParseCIDR(t)
				if err != nil {
					return false
				}
				if subnet.Contains(valueIp) {
					return true
				}
			}
			return false
		},
		NotEqualityFn: func(value string, target string) bool {
			return value != target
		},
		WildCardFn: func(value string, target string) bool {
			matches, err := filepath.Match(target, value)
			if err != nil {
				return false
			}
			return matches
		},
	}
}

// Evaluate evaluates an AST node with a given context
func (e *Evaluator) Evaluate(node Node, ctx *Context) (bool, error) {
	switch node.Type {
	case NODE_COMPOUND:
		return e.evaluateCompound(node, ctx)
	case NODE_EXPRESSION:
		if len(node.Children) == 1 {
			return e.Evaluate(node.Children[0], ctx)
		}
		return false, fmt.Errorf("invalid expression node")
	case NODE_STATEMENT:
		return e.evaluateStatement(node, ctx)
	default:
		return false, fmt.Errorf("unknown node type")
	}
}

func (e *Evaluator) evaluateCompound(node Node, ctx *Context) (bool, error) {
	if len(node.Children) < 1 {
		return false, fmt.Errorf("empty compound expression")
	}

	// Evaluate first child
	result, err := e.Evaluate(node.Children[0], ctx)
	if err != nil {
		return false, err
	}

	// Process remaining children in pairs (operator + expression)
	for i := 1; i < len(node.Children); i += 2 {
		if i+1 >= len(node.Children) {
			return false, fmt.Errorf("invalid compound expression")
		}

		operator := node.Children[i].Value
		rightValue, err := e.Evaluate(node.Children[i+1], ctx)
		if err != nil {
			return false, err
		}

		switch operator {
		case "and":
			result = result && rightValue
		case "or":
			result = result || rightValue
		default:
			return false, fmt.Errorf("unknown operator: %s", operator)
		}
	}

	return result, nil
}

func (e *Evaluator) evaluateStatement(node Node, ctx *Context) (bool, error) {
	parts := strings.Split(node.Value, " ")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid statement format")
	}

	field := parts[0]
	operator := parts[1]

	// Get the actual value from context
	value, exists := ctx.Variables[field]
	if !exists {
		return false, fmt.Errorf("undefined variable: %s", field)
	}

	if len(node.Children) != 1 {
		return false, fmt.Errorf("statement should have exactly one child")
	}

	valueNode := node.Children[0]

	var result bool

	switch operator {
	case "eq":
		if valueNode.Type != NODE_EXPRESSION {
			return false, fmt.Errorf("eq operator expects a single value")
		}
		result = e.EqualityFn(value, valueNode.Value)

	case "in":
		if valueNode.Value != "list" {
			return false, fmt.Errorf("in operator expects a list")
		}
		values := make([]string, len(valueNode.Children))
		for i, child := range valueNode.Children {
			values[i] = child.Value
		}

		if field == "ip" {
			result = e.InIpFn(value, values)
		} else {
			result = e.InFn(value, values)
		}

	case "ne":
		if valueNode.Type != NODE_EXPRESSION {
			return false, fmt.Errorf("ne operator expects a single value")
		}
		result = e.NotEqualityFn(value, valueNode.Value)

	case "wildcard":
		if valueNode.Type != NODE_EXPRESSION {
			return false, fmt.Errorf("ne operator expects a single value")
		}
		result = e.WildCardFn(value, valueNode.Value)

	default:
		return false, fmt.Errorf("unknown operator: %s", operator)
	}

	if node.Negated {
		result = !result
	}

	return result, nil
}

// ExpressionEvaluator wraps an AST and Evaluator for convenient evaluation
type ExpressionEvaluator struct {
	ast       Node
	evaluator *Evaluator
}

// Evaluate evaluates the expression with the given context
func (ee *ExpressionEvaluator) Evaluate(ctx *Context) (bool, error) {
	return ee.evaluator.Evaluate(ee.ast, ctx)
}

// NewExpressionEvaluator creates a new evaluator from an expression string
func NewExpressionEvaluator(expression string) (*ExpressionEvaluator, error) {
	// Create lexer and tokenize input
	lexer := NewLexer(expression)
	tokens, err := lexer.Tokenize()
	if err != nil {
		return nil, fmt.Errorf("lexer error: %v", err)
	}

	// Create parser and parse tokens
	parser := NewParser(tokens)
	ast, err := parser.Parse()
	if err != nil {
		return nil, fmt.Errorf("parser error: %v", err)
	}

	// Create evaluator with default implementations
	evaluator := NewEvaluator()

	return &ExpressionEvaluator{
		ast:       ast,
		evaluator: evaluator,
	}, nil
}

func (ee *ExpressionEvaluator) SetEqualityFn(fn func(value string, target string) bool) {
	ee.evaluator.EqualityFn = fn
}

func (ee *ExpressionEvaluator) SetInFn(fn func(value string, targets []string) bool) {
	ee.evaluator.InFn = fn
}

func (ee *ExpressionEvaluator) SetNotEqualityFn(fn func(value string, target string) bool) {
	ee.evaluator.NotEqualityFn = fn
}

func (ee *ExpressionEvaluator) SetWildCardFn(fn func(value string, target string) bool) {
	ee.evaluator.WildCardFn = fn
}
