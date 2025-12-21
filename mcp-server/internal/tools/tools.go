// Package tools implements all MCP tools for Amass
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/owasp-amass/amass/mcp-server/internal/cli"
	"github.com/owasp-amass/amass/mcp-server/internal/config"
	"github.com/owasp-amass/amass/mcp-server/internal/engine"
	"github.com/owasp-amass/amass/mcp-server/internal/graphql"
	"github.com/owasp-amass/amass/mcp-server/internal/types"
)

// Handler handles all MCP tool requests
type Handler struct {
	cliWrapper    *cli.Wrapper
	graphqlClient *graphql.Client
	engineManager *engine.Manager
	configManager *config.Manager
}

// NewHandler creates a new tools handler
func NewHandler(
	cliWrapper *cli.Wrapper,
	graphqlClient *graphql.Client,
	engineManager *engine.Manager,
	configManager *config.Manager,
) *Handler {
	return &Handler{
		cliWrapper:    cliWrapper,
		graphqlClient: graphqlClient,
		engineManager: engineManager,
		configManager: configManager,
	}
}

// EnumerateDomain starts domain enumeration
func (h *Handler) EnumerateDomain(ctx context.Context, input types.EnumerateDomainInput) (string, error) {
	log.Printf("[Tools] Starting enumeration for %s\n", input.Domain)

	// Ensure engine is running
	if err := h.engineManager.EnsureEngine(ctx); err != nil {
		return "", fmt.Errorf("failed to start engine: %w", err)
	}

	// Build configuration
	config := &types.AmassConfig{
		Scope: &types.ScopeConfig{
			Domains: []string{input.Domain},
		},
		Options: &types.OptionsConfig{
			Active:      !input.Passive,
			BruteForce:  input.BruteForce,
			Alterations: input.Alterations,
		},
	}

	if input.TimeoutMinutes > 0 {
		config.Timeout = input.TimeoutMinutes * 60
	}

	// Create session
	sessionToken, err := h.graphqlClient.CreateSession(ctx, config)
	if err != nil {
		return "", err
	}

	// Start monitoring progress in background
	go h.monitorProgress(context.Background(), sessionToken, input.Domain)

	return sessionToken, nil
}

// monitorProgress monitors enumeration progress
func (h *Handler) monitorProgress(ctx context.Context, sessionToken, domain string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats, err := h.graphqlClient.GetSessionStats(ctx, sessionToken)
			if err != nil {
				log.Printf("[Progress] Error checking progress: %v\n", err)
				return
			}

			if stats.WorkItemsTotal > 0 {
				progress := float64(stats.WorkItemsCompleted) / float64(stats.WorkItemsTotal) * 100
				log.Printf("[Progress] %s: %d/%d (%.2f%%)\n",
					domain, stats.WorkItemsCompleted, stats.WorkItemsTotal, progress)

				if stats.WorkItemsCompleted >= stats.WorkItemsTotal {
					log.Printf("[Progress] Enumeration complete for %s\n", domain)
					return
				}
			}
		}
	}
}

// ListSubdomains lists discovered subdomains
func (h *Handler) ListSubdomains(ctx context.Context, input types.ListSubdomainsInput) ([]types.SubdomainResult, error) {
	log.Printf("[Tools] Listing subdomains for %s\n", input.Domain)
	return h.cliWrapper.ListSubdomains(ctx, input)
}

// TrackChanges tracks changes in discovered assets
func (h *Handler) TrackChanges(ctx context.Context, input types.TrackChangesInput) ([]types.ChangeResult, error) {
	log.Printf("[Tools] Tracking changes for %s\n", input.Domain)
	return h.cliWrapper.TrackChanges(ctx, input)
}

// QueryAssociations queries asset associations
func (h *Handler) QueryAssociations(ctx context.Context, input types.QueryAssociationsInput) ([]types.AssociationResult, error) {
	log.Printf("[Tools] Querying associations for %s\n", input.Domain)
	return h.cliWrapper.QueryAssociations(ctx, input)
}

// GenerateVisualization generates a network visualization
func (h *Handler) GenerateVisualization(ctx context.Context, input types.GenerateVisualizationInput) (map[string]string, error) {
	log.Printf("[Tools] Generating %s visualization for %s\n", input.Format, input.Domain)

	// Determine output path
	outputPath := input.OutputPath
	if outputPath == "" {
		ext := h.getFileExtension(input.Format)
		outputPath = filepath.Join(os.TempDir(), fmt.Sprintf("amass-viz-%s-%d.%s",
			input.Domain, time.Now().Unix(), ext))
	}

	input.OutputPath = outputPath
	content, err := h.cliWrapper.GenerateVisualization(ctx, input)
	if err != nil {
		return nil, err
	}

	// Try to read the generated file
	fileContent := content
	if data, err := os.ReadFile(outputPath); err == nil {
		fileContent = string(data)
	}

	return map[string]string{
		"content":   fileContent,
		"file_path": outputPath,
	}, nil
}

// GetConfig gets Amass configuration
func (h *Handler) GetConfig(input types.GetConfigInput) (any, error) {
	log.Println("[Tools] Getting configuration")

	if input.Section != "" {
		section, err := h.configManager.GetConfigSection(input.Section)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"section": input.Section,
			"value":   section,
		}, nil
	}

	return h.configManager.GetConfig()
}

// UpdateConfig updates Amass configuration
func (h *Handler) UpdateConfig(input types.UpdateConfigInput) (map[string]any, error) {
	log.Println("[Tools] Updating configuration")

	updatedConfig, err := h.configManager.UpdateConfig(input.Updates)
	if err != nil {
		return nil, err
	}

	result := map[string]any{
		"success": true,
		"config":  updatedConfig,
	}

	if input.Validate {
		valid, errors := h.configManager.ValidateConfig(updatedConfig)
		result["validation"] = map[string]any{
			"valid":  valid,
			"errors": errors,
		}
	}

	return result, nil
}

// AddAPIKey adds or updates an API key
func (h *Handler) AddAPIKey(input types.AddAPIKeyInput) (map[string]any, error) {
	log.Printf("[Tools] Adding API key for %s\n", input.Source)

	if err := h.configManager.AddAPIKey(input.Source, input.APIKey, input.AdditionalConfig); err != nil {
		return nil, err
	}

	return map[string]any{
		"success": true,
		"source":  input.Source,
		"message": fmt.Sprintf("API key successfully added/updated for %s", input.Source),
	}, nil
}

// GetEngineStatus gets the engine status
func (h *Handler) GetEngineStatus(ctx context.Context) (types.EngineStatus, error) {
	log.Println("[Tools] Getting engine status")
	return h.engineManager.GetEngineStatus(ctx), nil
}

// ListDataSources lists all configured data sources
func (h *Handler) ListDataSources() ([]string, error) {
	log.Println("[Tools] Listing data sources")
	return h.configManager.ListDataSources()
}

// FormatJSON formats a value as JSON string
func (h *Handler) FormatJSON(v any) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// getFileExtension returns file extension based on format
func (h *Handler) getFileExtension(format string) string {
	switch format {
	case "d3":
		return "html"
	case "dot":
		return "dot"
	case "gexf":
		return "gexf"
	default:
		return "txt"
	}
}
