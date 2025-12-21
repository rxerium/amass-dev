// Simplified Amass MCP Server - Working Version
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

func main() {
	// Setup logging to stderr (stdout is used for MCP protocol)
	log.SetOutput(os.Stderr)
	log.SetPrefix("[MCP] ")

	// Environment configuration
	amassPath := getEnv("AMASS_PATH", "amass")
	engineURL := getEnv("AMASS_ENGINE_URL", "http://localhost:4000/graphql")
	configDir := getEnv("AMASS_CONFIG_DIR", "")

	log.Println("Starting Amass MCP Server...")
	log.Printf("Amass path: %s", amassPath)
	log.Printf("Engine URL: %s", engineURL)

	// Initialize components
	cliWrapper := cli.NewWrapper(amassPath)
	graphqlClient := graphql.NewClient(engineURL)
	engineManager := engine.NewManager(amassPath, engineURL, 30*time.Second, 5*time.Second)
	configManager := config.NewManager(configDir)
	toolsHandler := tools.NewHandler(cliWrapper, graphqlClient, engineManager, configManager)

	// Create server
	server := &MCPServer{
		handler: toolsHandler,
	}

	log.Println("Server started, waiting for requests...")

	// Process requests from stdin
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var request Request
		if err := json.Unmarshal([]byte(line), &request); err != nil {
			log.Printf("Error parsing request: %v", err)
			continue
		}

		response := server.HandleRequest(request)
		responseJSON, _ := json.Marshal(response)
		fmt.Println(string(responseJSON))
	}

	engineManager.Cleanup()
}

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *Error      `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type MCPServer struct {
	handler *tools.Handler
}

func (s *MCPServer) HandleRequest(req Request) Response {
	ctx := context.Background()

	switch req.Method {
	case "initialize":
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{},
				},
				"serverInfo": map[string]interface{}{
					"name":    "amass-mcp-server",
					"version": "1.0.0",
				},
			},
		}

	case "tools/list":
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"tools": []map[string]interface{}{
					{
						"name":        "amass_enumerate_domain",
						"description": "Perform subdomain enumeration on a target domain using Amass engine",
						"inputSchema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"domain": map[string]interface{}{
									"type":        "string",
									"description": "Target domain to enumerate (e.g., example.com)",
								},
								"passive": map[string]interface{}{
									"type":        "boolean",
									"description": "Use passive-only enumeration (no DNS resolution)",
								},
								"brute_force": map[string]interface{}{
									"type":        "boolean",
									"description": "Enable brute force techniques",
								},
							},
							"required": []string{"domain"},
						},
					},
					{
						"name":        "amass_list_subdomains",
						"description": "List all discovered subdomains for a domain from the Amass database",
						"inputSchema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"domain": map[string]interface{}{
									"type":        "string",
									"description": "Target domain to query",
								},
								"show_ips": map[string]interface{}{
									"type":        "boolean",
									"description": "Include IP addresses in results",
								},
							},
							"required": []string{"domain"},
						},
					},
					{
						"name":        "amass_engine_status",
						"description": "Check if the Amass engine (GraphQL server) is running and query its status",
						"inputSchema": map[string]interface{}{
							"type":       "object",
							"properties": map[string]interface{}{},
						},
					},
				},
			},
		}

	case "tools/call":
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &Error{Code: -32602, Message: "Invalid params"},
			}
		}

		result, err := s.executeTool(ctx, params.Name, params.Arguments)
		if err != nil {
			return Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &Error{Code: -32000, Message: err.Error()},
			}
		}

		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"content": []map[string]string{
					{"type": "text", "text": result},
				},
			},
		}

	default:
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &Error{Code: -32601, Message: "Method not found"},
		}
	}
}

func (s *MCPServer) executeTool(ctx context.Context, name string, args map[string]interface{}) (string, error) {
	switch name {
	case "amass_enumerate_domain":
		var input types.EnumerateDomainInput
		data, _ := json.Marshal(args)
		json.Unmarshal(data, &input)

		token, err := s.handler.EnumerateDomain(ctx, input)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Enumeration started for %s\nSession Token: %s", input.Domain, token), nil

	case "amass_list_subdomains":
		var input types.ListSubdomainsInput
		data, _ := json.Marshal(args)
		json.Unmarshal(data, &input)

		results, err := s.handler.ListSubdomains(ctx, input)
		if err != nil {
			return "", err
		}
		output, _ := s.handler.FormatJSON(results)
		return fmt.Sprintf("Found %d subdomains:\n\n%s", len(results), output), nil

	case "amass_engine_status":
		status, err := s.handler.GetEngineStatus(ctx)
		if err != nil {
			return "", err
		}
		output, _ := s.handler.FormatJSON(status)
		return fmt.Sprintf("Engine Status:\n\n%s", output), nil

	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
