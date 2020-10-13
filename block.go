// Package plugindemo a demo plugin.
package block

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"text/template"
)

// Config the plugin configuration.
type Config struct {
	BlockedRanges []string `json:"blockedranges,omitempty" toml:"blockedranges,omitempty" yaml:"blockedranges,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		BlockedRanges: []string{},
	}
}

// Block is a plugin that blocks incoming requests depending on their source IP.
type Block struct {
	next     http.Handler
	checker  *Checker
	name     string
	template *template.Template
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.BlockedRanges) == 0 {
		fmt.Println("No IPs defined for block")
	}

	checker, err := NewChecker(config.BlockedRanges)
	if err != nil {
		return nil, fmt.Errorf("cannot parse CIDR whitelist %s: %w", config.BlockedRanges, err)
	}

	return &Block{
		checker:  checker,
		next:     next,
		name:     name,
		template: template.New("demo").Delims("[[", "]]"),
	}, nil
}

func (b *Block) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	sourceIP := strings.Split(req.RemoteAddr, ":")[0]
	err := b.checker.IsAuthorized(sourceIP)
	if err == nil {
		fmt.Printf("rejecting request %+v: %v", req, err)
		fmt.Println("The IP has been blocked since it was included in the blocklist")
		reject(rw)
		return
	}
	fmt.Printf("Accept %s: %+v", sourceIP, req)

	b.next.ServeHTTP(rw, req)
}

func reject(rw http.ResponseWriter) {
	statusCode := http.StatusForbidden

	rw.WriteHeader(statusCode)
	_, err := rw.Write([]byte(http.StatusText(statusCode)))
	if err != nil {
		fmt.Println(err)
	}
}
