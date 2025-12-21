// Amass MCP Server - Complete Rewrite
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/owasp-amass/amass/mcp-server/internal/cli"
	"github.com/owasp-amass/amass/mcp-server/internal/config"
	"github.com/owasp-amass/amass/mcp-server/internal/engine"
	"github.com/owasp-amass/amass/mcp-server/internal/graphql"
	"github.com/owasp-amass/amass/mcp-server/internal/tools"
	"github.com/owasp-amass/amass/mcp-server/internal/types"
)

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int            `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      *int        `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("[MCP] ")

	// Try to find amass in common locations
	amassPath := getEnv("AMASS_PATH", "")
	if amassPath == "" {
		// Check common locations
		possiblePaths := []string{
			"/Users/rxerium/go/bin/amass",
			"/usr/local/bin/amass",
			"/opt/homebrew/bin/amass",
			"amass", // fallback to PATH
		}
		for _, path := range possiblePaths {
			if _, err := os.Stat(path); err == nil {
				amassPath = path
				log.Printf("Found amass at: %s\n", path)
				break
			}
		}
		if amassPath == "" {
			amassPath = "amass" // ultimate fallback
		}
	}

	engineURL := getEnv("AMASS_ENGINE_URL", "http://localhost:4000/graphql")
	configDir := getEnv("AMASS_CONFIG_DIR", "")

	log.Printf("Starting Amass MCP Server v1.0.0 (using amass: %s)\n", amassPath)

	cliWrapper := cli.NewWrapper(amassPath)
	graphqlClient := graphql.NewClient(engineURL)
	engineManager := engine.NewManager(amassPath, engineURL, 30*time.Second, 5*time.Second)
	configManager := config.NewManager(configDir)
	handler := tools.NewHandler(cliWrapper, graphqlClient, engineManager, configManager)

	server := &Server{handler: handler}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		response := server.Handle([]byte(line))
		if response != nil {
			fmt.Println(string(response))
		}
	}

	engineManager.Cleanup()
}

type Server struct {
	handler *tools.Handler
}

func (s *Server) Handle(data []byte) []byte {
	var req JSONRPCRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return s.error(nil, -32700, "Parse error", nil)
	}

	switch req.Method {
	case "initialize":
		return s.initialize(req.ID)
	case "initialized", "notifications/initialized":
		// Notification - no response needed
		return nil
	case "tools/list":
		return s.toolsList(req.ID)
	case "tools/call":
		return s.toolsCall(req.ID, req.Params)
	default:
		return s.error(req.ID, -32601, "Method not found", nil)
	}
}

func (s *Server) initialize(id *int) []byte {
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "amass-mcp-server",
			"version": "1.0.0",
		},
	}
	return s.success(id, result)
}

func (s *Server) toolsList(id *int) []byte {
	tools := []map[string]interface{}{
		{
			"name":        "amass_enumerate_domain",
			"description": "Start subdomain enumeration for a target domain. The Amass engine will be started automatically if not running.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]string{
						"type":        "string",
						"description": "Target domain (e.g., example.com)",
					},
				},
				"required": []string{"domain"},
			},
		},
		{
			"name":        "amass_list_subdomains",
			"description": "List discovered subdomains from an enumeration session. If session_token is provided, it will fetch results from that specific session. Otherwise, it will try to find results for the domain.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]string{
						"type":        "string",
						"description": "Domain to query",
					},
					"session_token": map[string]string{
						"type":        "string",
						"description": "Optional session token from enumerate_domain to fetch specific session results",
					},
					"show_ips": map[string]string{
						"type":        "boolean",
						"description": "Include IP addresses (may not work with session token method)",
					},
				},
				"required": []string{"domain"},
			},
		},
		{
			"name":        "amass_scan_status",
			"description": "Check the status of enumeration scans. Shows running/completed scans with elapsed time and PID.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]string{
						"type":        "string",
						"description": "Optional: specific domain to check. If omitted, shows all scans.",
					},
				},
			},
		},
		{
			"name":        "amass_engine_status",
			"description": "Check if Amass engine is running",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":        "amass_track_changes",
			"description": "Track changes in discovered assets over time. Monitors new, modified, or deleted assets.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]string{
						"type":        "string",
						"description": "Domain to track changes for",
					},
					"since": map[string]string{
						"type":        "string",
						"description": "Time period (e.g., '24h', '7d', '30d')",
					},
				},
				"required": []string{"domain", "since"},
			},
		},
		{
			"name":        "amass_query_associations",
			"description": "Query asset associations and relationships. Discover related infrastructure like shared IPs, ASNs, and certificates.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]string{
						"type":        "string",
						"description": "Domain to query associations for",
					},
					"walk_pattern": map[string]string{
						"type":        "string",
						"description": "Optional: graph walk pattern for traversal",
					},
				},
				"required": []string{"domain"},
			},
		},
		{
			"name":        "amass_generate_visualization",
			"description": "Generate network visualization of discovered assets. Supports D3.js (interactive HTML), DOT (Graphviz), and GEXF formats.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]string{
						"type":        "string",
						"description": "Domain to visualize",
					},
					"format": map[string]string{
						"type":        "string",
						"description": "Output format: 'd3' (HTML), 'dot' (Graphviz), or 'gexf'",
					},
					"output_path": map[string]string{
						"type":        "string",
						"description": "Optional: custom output file path",
					},
				},
				"required": []string{"domain", "format"},
			},
		},
		{
			"name":        "amass_get_config",
			"description": "Get current Amass configuration. Can retrieve full config or specific sections.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"section": map[string]string{
						"type":        "string",
						"description": "Optional: specific config section (e.g., 'scope', 'datasources')",
					},
				},
			},
		},
		{
			"name":        "amass_update_config",
			"description": "Update Amass configuration settings. Can modify scope, options, data sources, etc.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"updates": map[string]string{
						"type":        "object",
						"description": "Configuration updates as key-value pairs",
					},
					"validate": map[string]string{
						"type":        "boolean",
						"description": "Validate configuration after update",
					},
				},
				"required": []string{"updates"},
			},
		},
		{
			"name":        "amass_add_api_key",
			"description": "Add or update API keys for data sources. Enables premium features from services like SecurityTrails, Shodan, etc.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"source": map[string]string{
						"type":        "string",
						"description": "Data source name (e.g., 'SecurityTrails', 'Shodan', 'VirusTotal')",
					},
					"api_key": map[string]string{
						"type":        "string",
						"description": "API key for the data source",
					},
					"additional_config": map[string]string{
						"type":        "object",
						"description": "Optional: additional configuration for the source",
					},
				},
				"required": []string{"source", "api_key"},
			},
		},
		{
			"name":        "amass_list_data_sources",
			"description": "List all available and configured data sources. Shows which services are active.",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":        "amass_get_ip_addresses",
			"description": "Get all IP addresses associated with a domain from the Amass database.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]string{
						"type":        "string",
						"description": "Domain to query IP addresses for",
					},
				},
				"required": []string{"domain"},
			},
		},
		{
			"name":        "amass_get_whois_data",
			"description": "Get WHOIS and contact record information for a domain.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]string{
						"type":        "string",
						"description": "Domain to query WHOIS data for",
					},
				},
				"required": []string{"domain"},
			},
		},
		{
			"name":        "amass_get_domain_info",
			"description": "Get detailed domain record information from the Amass database.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]string{
						"type":        "string",
						"description": "Domain to query information for",
					},
				},
				"required": []string{"domain"},
			},
		},
		{
			"name":        "amass_get_all_assets",
			"description": "Get all discovered assets for a domain across all entity types (subdomains, IPs, ASNs, etc.).",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]string{
						"type":        "string",
						"description": "Domain to query all assets for",
					},
				},
				"required": []string{"domain"},
			},
		},
		{
			"name":        "amass_get_relationships",
			"description": "Get relationships and associations between assets from the graph database.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]string{
						"type":        "string",
						"description": "Domain to query relationships for",
					},
				},
				"required": []string{"domain"},
			},
		},
	}

	return s.success(id, map[string]interface{}{"tools": tools})
}

func (s *Server) toolsCall(id *int, params json.RawMessage) []byte {
	var p struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}

	if err := json.Unmarshal(params, &p); err != nil {
		return s.error(id, -32602, "Invalid params", nil)
	}

	text, err := s.executeTool(p.Name, p.Arguments)
	if err != nil {
		return s.error(id, -32000, err.Error(), nil)
	}

	result := map[string]interface{}{
		"content": []map[string]string{
			{"type": "text", "text": text},
		},
	}

	return s.success(id, result)
}

func (s *Server) executeTool(name string, args map[string]interface{}) (string, error) {
	ctx := context.Background()

	switch name {
	case "amass_enumerate_domain":
		domain, _ := args["domain"].(string)
		if domain == "" {
			return "", fmt.Errorf("domain is required")
		}

		passive, _ := args["passive"].(bool)

		result, err := s.handler.EnumerateDomainDirect(ctx, domain, passive)
		if err != nil {
			return "", err
		}

		return result, nil

	case "amass_list_subdomains":
		domain, _ := args["domain"].(string)
		if domain == "" {
			return "", fmt.Errorf("domain is required")
		}

		showIPs, _ := args["show_ips"].(bool)
		sessionToken, _ := args["session_token"].(string)
		input := types.ListSubdomainsInput{
			Domain:       domain,
			SessionToken: sessionToken,
			ShowIPs:      showIPs,
		}

		results, err := s.handler.ListSubdomains(ctx, input)
		if err != nil {
			return "", err
		}

		if len(results) == 0 {
			return fmt.Sprintf("No subdomains found for %s\n\nTip: Run 'amass_enumerate_domain' first to discover subdomains.", domain), nil
		}

		output, _ := s.handler.FormatJSON(results)
		return fmt.Sprintf("Found %d subdomains for %s:\n\n%s", len(results), domain, output), nil

	case "amass_scan_status":
		domain, _ := args["domain"].(string)

		status, err := s.handler.GetScanStatus(ctx, domain)
		if err != nil {
			return "", err
		}

		return status, nil

	case "amass_engine_status":
		status, err := s.handler.GetEngineStatus(ctx)
		if err != nil {
			return "", err
		}

		output, _ := s.handler.FormatJSON(status)
		return fmt.Sprintf("Amass Engine Status:\n\n%s", output), nil

	case "amass_track_changes":
		domain, _ := args["domain"].(string)
		if domain == "" {
			return "", fmt.Errorf("domain is required")
		}
		since, _ := args["since"].(string)
		if since == "" {
			return "", fmt.Errorf("since is required")
		}

		input := types.TrackChangesInput{
			Domain: domain,
			Since:  since,
		}

		results, err := s.handler.TrackChanges(ctx, input)
		if err != nil {
			return "", err
		}

		if len(results) == 0 {
			return fmt.Sprintf("No changes detected for %s in the last %s", domain, since), nil
		}

		output, _ := s.handler.FormatJSON(results)
		return fmt.Sprintf("Found %d changes for %s:\n\n%s", len(results), domain, output), nil

	case "amass_query_associations":
		domain, _ := args["domain"].(string)
		if domain == "" {
			return "", fmt.Errorf("domain is required")
		}

		walkPattern, _ := args["walk_pattern"].(string)
		input := types.QueryAssociationsInput{
			Domain:      domain,
			WalkPattern: walkPattern,
		}

		results, err := s.handler.QueryAssociations(ctx, input)
		if err != nil {
			return "", err
		}

		if len(results) == 0 {
			return fmt.Sprintf("No associations found for %s", domain), nil
		}

		output, _ := s.handler.FormatJSON(results)
		return fmt.Sprintf("Found %d associations for %s:\n\n%s", len(results), domain, output), nil

	case "amass_generate_visualization":
		domain, _ := args["domain"].(string)
		if domain == "" {
			return "", fmt.Errorf("domain is required")
		}
		format, _ := args["format"].(string)
		if format == "" {
			return "", fmt.Errorf("format is required")
		}

		outputPath, _ := args["output_path"].(string)
		input := types.GenerateVisualizationInput{
			Domain:     domain,
			Format:     format,
			OutputPath: outputPath,
		}

		result, err := s.handler.GenerateVisualization(ctx, input)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("Visualization generated for %s:\n\nFormat: %s\nFile: %s\n\n%s",
			domain, format, result["file_path"], result["content"]), nil

	case "amass_get_config":
		section, _ := args["section"].(string)
		input := types.GetConfigInput{
			Section: section,
		}

		config, err := s.handler.GetConfig(input)
		if err != nil {
			return "", err
		}

		output, _ := s.handler.FormatJSON(config)
		return fmt.Sprintf("Amass Configuration:\n\n%s", output), nil

	case "amass_update_config":
		updates, ok := args["updates"].(map[string]interface{})
		if !ok || len(updates) == 0 {
			return "", fmt.Errorf("updates is required")
		}

		validate, _ := args["validate"].(bool)
		input := types.UpdateConfigInput{
			Updates:  updates,
			Validate: validate,
		}

		result, err := s.handler.UpdateConfig(input)
		if err != nil {
			return "", err
		}

		output, _ := s.handler.FormatJSON(result)
		return fmt.Sprintf("Configuration updated:\n\n%s", output), nil

	case "amass_add_api_key":
		source, _ := args["source"].(string)
		if source == "" {
			return "", fmt.Errorf("source is required")
		}
		apiKey, _ := args["api_key"].(string)
		if apiKey == "" {
			return "", fmt.Errorf("api_key is required")
		}

		additionalConfig, _ := args["additional_config"].(map[string]interface{})
		input := types.AddAPIKeyInput{
			Source:           source,
			APIKey:           apiKey,
			AdditionalConfig: additionalConfig,
		}

		result, err := s.handler.AddAPIKey(input)
		if err != nil {
			return "", err
		}

		output, _ := s.handler.FormatJSON(result)
		return output, nil

	case "amass_list_data_sources":
		sources, err := s.handler.ListDataSources()
		if err != nil {
			return "", err
		}

		output, _ := s.handler.FormatJSON(sources)
		return fmt.Sprintf("Available Data Sources:\n\n%s", output), nil

	case "amass_get_ip_addresses":
		domain, _ := args["domain"].(string)
		if domain == "" {
			return "", fmt.Errorf("domain is required")
		}

		result, err := s.handler.GetIPAddresses(ctx, domain)
		if err != nil {
			return "", err
		}

		output, _ := s.handler.FormatJSON(result)
		return fmt.Sprintf("IP Addresses for %s:\n\n%s", domain, output), nil

	case "amass_get_whois_data":
		domain, _ := args["domain"].(string)
		if domain == "" {
			return "", fmt.Errorf("domain is required")
		}

		result, err := s.handler.GetWhoisData(ctx, domain)
		if err != nil {
			return "", err
		}

		output, _ := s.handler.FormatJSON(result)
		return fmt.Sprintf("WHOIS Data for %s:\n\n%s", domain, output), nil

	case "amass_get_domain_info":
		domain, _ := args["domain"].(string)
		if domain == "" {
			return "", fmt.Errorf("domain is required")
		}

		result, err := s.handler.GetDomainInfo(ctx, domain)
		if err != nil {
			return "", err
		}

		output, _ := s.handler.FormatJSON(result)
		return fmt.Sprintf("Domain Information for %s:\n\n%s", domain, output), nil

	case "amass_get_all_assets":
		domain, _ := args["domain"].(string)
		if domain == "" {
			return "", fmt.Errorf("domain is required")
		}

		result, err := s.handler.GetAllAssets(ctx, domain)
		if err != nil {
			return "", err
		}

		output, _ := s.handler.FormatJSON(result)
		return fmt.Sprintf("All Assets for %s:\n\n%s", domain, output), nil

	case "amass_get_relationships":
		domain, _ := args["domain"].(string)
		if domain == "" {
			return "", fmt.Errorf("domain is required")
		}

		result, err := s.handler.GetRelationships(ctx, domain)
		if err != nil {
			return "", err
		}

		output, _ := s.handler.FormatJSON(result)
		return fmt.Sprintf("Relationships for %s:\n\n%s", domain, output), nil

	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

func (s *Server) success(id *int, result interface{}) []byte {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	data, _ := json.Marshal(resp)
	return data
}

func (s *Server) error(id *int, code int, message string, data interface{}) []byte {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
	respData, _ := json.Marshal(resp)
	return respData
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
