// Package graphql provides a GraphQL client for the Amass engine
package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/owasp-amass/amass/mcp-server/internal/types"
)

// Client wraps the GraphQL client for Amass engine
type Client struct {
	httpClient *http.Client
	engineURL  string
}

// NewClient creates a new GraphQL client
func NewClient(engineURL string) *Client {
	return &Client{
		httpClient: &http.Client{},
		engineURL:  engineURL,
	}
}

// CreateSession creates a new enumeration session
func (c *Client) CreateSession(ctx context.Context, config *types.AmassConfig) (string, error) {
	log.Println("[GraphQL] Creating enumeration session")

	// Convert config to a map for the GraphQL mutation
	configMap := map[string]any{}

	if config.Scope != nil {
		scopeMap := map[string]any{}
		if config.Scope.Domains != nil && len(config.Scope.Domains) > 0 {
			scopeMap["domains"] = config.Scope.Domains
		}
		if config.Scope.IPs != nil && len(config.Scope.IPs) > 0 {
			scopeMap["ips"] = config.Scope.IPs
		}
		if config.Scope.CIDRs != nil && len(config.Scope.CIDRs) > 0 {
			scopeMap["cidrs"] = config.Scope.CIDRs
		}
		if config.Scope.ASNs != nil && len(config.Scope.ASNs) > 0 {
			scopeMap["asns"] = config.Scope.ASNs
		}
		if config.Scope.Ports != nil && len(config.Scope.Ports) > 0 {
			scopeMap["ports"] = config.Scope.Ports
		}
		if len(scopeMap) > 0 {
			configMap["scope"] = scopeMap
		}
	}

	if config.Options != nil {
		optionsMap := map[string]any{
			"active": config.Options.Active,
		}
		if config.Options.BruteForce {
			optionsMap["brute_force"] = true
		}
		if config.Options.Alterations {
			optionsMap["alterations"] = true
		}
		if config.Options.Recursive {
			optionsMap["recursive"] = true
		}
		if config.Options.MinForRecursive > 0 {
			optionsMap["minimum_for_recursive"] = config.Options.MinForRecursive
		}
		configMap["options"] = optionsMap
	}

	if config.DataSources != nil {
		configMap["datasources"] = config.DataSources
	}
	if config.MaxDNS > 0 {
		configMap["max_dns_queries"] = config.MaxDNS
	}
	if config.Timeout > 0 {
		configMap["timeout"] = config.Timeout
	}

	log.Printf("[GraphQL] Config map: %+v\n", configMap)

	// Use raw HTTP request instead of graphql-client library
	requestBody := map[string]any{
		"query": "mutation CreateSession($input: CreateSessionInput!) { createSession(input: $input) { sessionToken } }",
		"variables": map[string]any{
			"input": map[string]any{
				"config": configMap,
			},
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	log.Printf("[GraphQL] Sending HTTP request\n")

	req, err := http.NewRequestWithContext(ctx, "POST", c.engineURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var result struct {
		Data struct {
			CreateSession struct {
				SessionToken string `json:"sessionToken"`
			} `json:"createSession"`
		} `json:"data"`
		Errors []map[string]any `json:"errors"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Errors) > 0 {
		return "", fmt.Errorf("graphql errors: %+v", result.Errors)
	}

	sessionToken := result.Data.CreateSession.SessionToken
	log.Printf("[GraphQL] Session created: %s\n", sessionToken)
	return sessionToken, nil
}

// GetSessionStats gets session statistics (progress)
func (c *Client) GetSessionStats(ctx context.Context, sessionToken string) (*types.SessionStats, error) {
	log.Printf("[GraphQL] Getting stats for session %s\n", sessionToken)

	requestBody := map[string]any{
		"query": "query GetStats($token: String!) { sessionStats(sessionToken: $token) { WorkItemsCompleted WorkItemsTotal } }",
		"variables": map[string]any{
			"token": sessionToken,
		},
	}

	jsonData, _ := json.Marshal(requestBody)
	req, _ := http.NewRequestWithContext(ctx, "POST", c.engineURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Data struct {
			SessionStats struct {
				WorkItemsCompleted int `json:"WorkItemsCompleted"`
				WorkItemsTotal     int `json:"WorkItemsTotal"`
			} `json:"sessionStats"`
		} `json:"data"`
		Errors []map[string]any `json:"errors"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("graphql errors: %+v", result.Errors)
	}

	return &types.SessionStats{
		WorkItemsCompleted: result.Data.SessionStats.WorkItemsCompleted,
		WorkItemsTotal:     result.Data.SessionStats.WorkItemsTotal,
	}, nil
}

// TerminateSession terminates a session
func (c *Client) TerminateSession(ctx context.Context, sessionToken string) error {
	log.Printf("[GraphQL] Terminating session %s\n", sessionToken)

	requestBody := map[string]any{
		"query": "mutation Terminate($token: String!) { terminateSession(sessionToken: $token) }",
		"variables": map[string]any{
			"token": sessionToken,
		},
	}

	jsonData, _ := json.Marshal(requestBody)
	req, _ := http.NewRequestWithContext(ctx, "POST", c.engineURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	log.Println("[GraphQL] Session terminated successfully")
	return nil
}

// GetFindings gets the findings (discovered assets) for a session
func (c *Client) GetFindings(ctx context.Context, sessionToken string) ([]string, error) {
	log.Printf("[GraphQL] Getting findings for session %s\n", sessionToken)

	requestBody := map[string]any{
		"query": `query GetFindings($token: String!) {
			findings(sessionToken: $token, limit: 1000) {
				fqdn
			}
		}`,
		"variables": map[string]any{
			"token": sessionToken,
		},
	}

	jsonData, _ := json.Marshal(requestBody)
	req, _ := http.NewRequestWithContext(ctx, "POST", c.engineURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Data struct {
			Findings []struct {
				FQDN string `json:"fqdn"`
			} `json:"findings"`
		} `json:"data"`
		Errors []map[string]any `json:"errors"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("graphql errors: %+v", result.Errors)
	}

	var fqdns []string
	for _, finding := range result.Data.Findings {
		fqdns = append(fqdns, finding.FQDN)
	}

	log.Printf("[GraphQL] Found %d subdomains\n", len(fqdns))
	return fqdns, nil
}
