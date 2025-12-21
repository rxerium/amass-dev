// Amass MCP Server - Main entry point
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mark3labs/mcphost"

	"github.com/owasp-amass/amass/mcp-server/internal/cli"
	"github.com/owasp-amass/amass/mcp-server/internal/config"
	"github.com/owasp-amass/amass/mcp-server/internal/engine"
	"github.com/owasp-amass/amass/mcp-server/internal/graphql"
	"github.com/owasp-amass/amass/mcp-server/internal/tools"
	"github.com/owasp-amass/amass/mcp-server/internal/types"
)

// getEnv gets an environment variable with a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	// Environment configuration
	amassPath := getEnv("AMASS_PATH", "amass")
	engineURL := getEnv("AMASS_ENGINE_URL", "http://localhost:4000/graphql")
	configDir := getEnv("AMASS_CONFIG_DIR", "")

	log.Println("[MCP Server] Starting Amass MCP Server...")
	log.Printf("[MCP Server] Amass path: %s\n", amassPath)
	log.Printf("[MCP Server] Engine URL: %s\n", engineURL)
	if configDir == "" {
		log.Println("[MCP Server] Config dir: ~/.config/amass")
	} else {
		log.Printf("[MCP Server] Config dir: %s\n", configDir)
	}

	// Initialize components
	cliWrapper := cli.NewWrapper(amassPath)
	graphqlClient := graphql.NewClient(engineURL)
	engineManager := engine.NewManager(amassPath, engineURL, 30*time.Second, 5*time.Second)
	configManager := config.NewManager(configDir)

	// Initialize tools handler
	toolsHandler := tools.NewHandler(cliWrapper, graphqlClient, engineManager, configManager)

	// Create MCP server
	mcpServer := mcphost.NewServer(
		"amass-mcp-server",
		"1.0.0",
	)

	// Register tools
	registerTools(mcpServer, toolsHandler)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\n[MCP Server] Shutting down...")
		engineManager.Cleanup()
		os.Exit(0)
	}()

	// Start server
	log.Println("[MCP Server] Server started successfully")
	if err := server.ServeStdio(mcpServer); err != nil {
		log.Fatalf("[MCP Server] Fatal error: %v\n", err)
	}
}

func registerTools(s *server.MCPServer, h *tools.Handler) {
	// Tool 1: amass_enumerate_domain
	s.AddTool(mcp.Tool{
		Name:        "amass_enumerate_domain",
		Description: "Perform subdomain enumeration on a target domain using Amass engine. Returns a session token for tracking progress.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"domain":          map[string]string{"type": "string", "description": "Target domain (e.g., example.com)"},
				"passive":         map[string]string{"type": "boolean", "description": "Use passive-only enumeration"},
				"brute_force":     map[string]string{"type": "boolean", "description": "Enable brute force"},
				"alterations":     map[string]string{"type": "boolean", "description": "Enable alterations"},
				"timeout_minutes": map[string]string{"type": "number", "description": "Timeout in minutes"},
			},
			Required: []string{"domain"},
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		var input types.EnumerateDomainInput
		data, _ := json.Marshal(args)
		json.Unmarshal(data, &input)

		sessionToken, err := h.EnumerateDomain(context.Background(), input)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf(
			"Enumeration started for %s\nSession Token: %s\n\nThe enumeration is running in the background.\nUse amass_list_subdomains to retrieve results when complete.",
			input.Domain, sessionToken,
		)), nil
	})

	// Tool 2: amass_list_subdomains
	s.AddTool(mcp.Tool{
		Name:        "amass_list_subdomains",
		Description: "List all discovered subdomains for a domain from the Amass database.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"domain":          map[string]string{"type": "string", "description": "Target domain"},
				"show_ips":        map[string]string{"type": "boolean", "description": "Include IP addresses"},
				"show_ipv4_only":  map[string]string{"type": "boolean", "description": "Show only IPv4"},
				"show_ipv6_only":  map[string]string{"type": "boolean", "description": "Show only IPv6"},
			},
			Required: []string{"domain"},
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		var input types.ListSubdomainsInput
		data, _ := json.Marshal(args)
		json.Unmarshal(data, &input)

		results, err := h.ListSubdomains(context.Background(), input)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
		}

		output, _ := h.FormatJSON(results)
		return mcp.NewToolResultText(fmt.Sprintf("Found %d subdomains:\n\n%s", len(results), output)), nil
	})

	// Tool 3: amass_track_changes
	s.AddTool(mcp.Tool{
		Name:        "amass_track_changes",
		Description: "Track changes in discovered assets since a specific time.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"domain": map[string]string{"type": "string", "description": "Target domain"},
				"since":  map[string]string{"type": "string", "description": "Track since (01/02 15:04:05 2006 MST)"},
			},
			Required: []string{"domain", "since"},
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		var input types.TrackChangesInput
		data, _ := json.Marshal(args)
		json.Unmarshal(data, &input)

		results, err := h.TrackChanges(context.Background(), input)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
		}

		output, _ := h.FormatJSON(results)
		return mcp.NewToolResultText(fmt.Sprintf("Found %d changes:\n\n%s", len(results), output)), nil
	})

	// Tool 4: amass_query_associations
	s.AddTool(mcp.Tool{
		Name:        "amass_query_associations",
		Description: "Query the OAM database for asset associations using graph traversal.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"domain":       map[string]string{"type": "string", "description": "Starting domain"},
				"walk_pattern": map[string]string{"type": "string", "description": "Optional walk pattern"},
			},
			Required: []string{"domain"},
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		var input types.QueryAssociationsInput
		data, _ := json.Marshal(args)
		json.Unmarshal(data, &input)

		results, err := h.QueryAssociations(context.Background(), input)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
		}

		output, _ := h.FormatJSON(results)
		return mcp.NewToolResultText(fmt.Sprintf("Found %d associations:\n\n%s", len(results), output)), nil
	})

	// Tool 5: amass_generate_visualization
	s.AddTool(mcp.Tool{
		Name:        "amass_generate_visualization",
		Description: "Generate network visualization in D3, DOT, or GEXF format.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"domain":      map[string]string{"type": "string", "description": "Target domain"},
				"format":      map[string]string{"type": "string", "description": "Format: d3, dot, or gexf"},
				"output_path": map[string]string{"type": "string", "description": "Optional output path"},
			},
			Required: []string{"domain", "format"},
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		var input types.GenerateVisualizationInput
		data, _ := json.Marshal(args)
		json.Unmarshal(data, &input)

		result, err := h.GenerateVisualization(context.Background(), input)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf(
			"Visualization generated successfully!\n\nFile path: %s\n\nContent length: %d characters",
			result["file_path"], len(result["content"]),
		)), nil
	})

	// Tool 6: amass_get_config
	s.AddTool(mcp.Tool{
		Name:        "amass_get_config",
		Description: "Read current Amass configuration from ~/.config/amass/config.yaml.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"section": map[string]string{"type": "string", "description": "Optional config section"},
			},
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		var input types.GetConfigInput
		data, _ := json.Marshal(args)
		json.Unmarshal(data, &input)

		config, err := h.GetConfig(input)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
		}

		output, _ := h.FormatJSON(config)
		return mcp.NewToolResultText(fmt.Sprintf("Configuration:\n\n%s", output)), nil
	})

	// Tool 7: amass_update_config
	s.AddTool(mcp.Tool{
		Name:        "amass_update_config",
		Description: "Update Amass configuration file with new settings.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"updates":  map[string]string{"type": "object", "description": "Configuration updates"},
				"validate": map[string]string{"type": "boolean", "description": "Validate config"},
			},
			Required: []string{"updates"},
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		var input types.UpdateConfigInput
		data, _ := json.Marshal(args)
		json.Unmarshal(data, &input)

		result, err := h.UpdateConfig(input)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
		}

		output, _ := h.FormatJSON(result)
		return mcp.NewToolResultText(fmt.Sprintf("Configuration updated successfully!\n\n%s", output)), nil
	})

	// Tool 8: amass_add_api_key
	s.AddTool(mcp.Tool{
		Name:        "amass_add_api_key",
		Description: "Add or update API key for a data source in Amass configuration.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"source":            map[string]string{"type": "string", "description": "Data source name"},
				"api_key":           map[string]string{"type": "string", "description": "API key value"},
				"additional_config": map[string]string{"type": "object", "description": "Additional config"},
			},
			Required: []string{"source", "api_key"},
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		var input types.AddAPIKeyInput
		data, _ := json.Marshal(args)
		json.Unmarshal(data, &input)

		result, err := h.AddAPIKey(input)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("%s\n\nSource: %s", result["message"], result["source"])), nil
	})

	// Tool 9: amass_engine_status
	s.AddTool(mcp.Tool{
		Name:        "amass_engine_status",
		Description: "Check if the Amass engine (GraphQL server) is running and query its status.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		status, err := h.GetEngineStatus(context.Background())
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
		}

		output, _ := h.FormatJSON(status)
		return mcp.NewToolResultText(fmt.Sprintf("Engine Status:\n\n%s", output)), nil
	})

	// Tool 10: amass_list_data_sources
	s.AddTool(mcp.Tool{
		Name:        "amass_list_data_sources",
		Description: "List all data sources configured in Amass that can be used for enumeration.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		sources, err := h.ListDataSources()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
		}

		output := ""
		for i, source := range sources {
			output += fmt.Sprintf("%d. %s\n", i+1, source)
		}

		return mcp.NewToolResultText(fmt.Sprintf("Configured Data Sources (%d):\n\n%s", len(sources), output)), nil
	})
}
