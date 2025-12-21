// Package graphql provides a GraphQL client for the Amass engine
package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hasura/go-graphql-client"

	"github.com/owasp-amass/amass/mcp-server/internal/types"
)

// Client wraps the GraphQL client for Amass engine
type Client struct {
	client    *graphql.Client
	engineURL string
}

// NewClient creates a new GraphQL client
func NewClient(engineURL string) *Client {
	return &Client{
		client:    graphql.NewClient(engineURL, nil),
		engineURL: engineURL,
	}
}

// CreateSession creates a new enumeration session
func (c *Client) CreateSession(ctx context.Context, config *types.AmassConfig) (string, error) {
	log.Println("[GraphQL] Creating enumeration session")

	configJSON, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}

	var mutation struct {
		CreateSessionFromJSON string `graphql:"createSessionFromJson(input: $config)"`
	}

	variables := map[string]any{
		"config": string(configJSON),
	}

	if err := c.client.Mutate(ctx, &mutation, variables); err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	log.Printf("[GraphQL] Session created: %s\n", mutation.CreateSessionFromJSON)
	return mutation.CreateSessionFromJSON, nil
}

// GetSessionStats gets session statistics (progress)
func (c *Client) GetSessionStats(ctx context.Context, sessionToken string) (*types.SessionStats, error) {
	log.Printf("[GraphQL] Getting stats for session %s\n", sessionToken)

	var query struct {
		SessionStats struct {
			WorkItemsCompleted int
			WorkItemsTotal     int
		} `graphql:"sessionStats(sessionToken: $token)"`
	}

	variables := map[string]any{
		"token": sessionToken,
	}

	if err := c.client.Query(ctx, &query, variables); err != nil {
		return nil, fmt.Errorf("failed to get session stats: %w", err)
	}

	stats := &types.SessionStats{
		WorkItemsCompleted: query.SessionStats.WorkItemsCompleted,
		WorkItemsTotal:     query.SessionStats.WorkItemsTotal,
	}

	return stats, nil
}

// TerminateSession terminates a session
func (c *Client) TerminateSession(ctx context.Context, sessionToken string) error {
	log.Printf("[GraphQL] Terminating session %s\n", sessionToken)

	var mutation struct {
		TerminateSession bool `graphql:"terminateSession(sessionToken: $token)"`
	}

	variables := map[string]any{
		"token": sessionToken,
	}

	if err := c.client.Mutate(ctx, &mutation, variables); err != nil {
		return fmt.Errorf("failed to terminate session: %w", err)
	}

	log.Println("[GraphQL] Session terminated successfully")
	return nil
}
