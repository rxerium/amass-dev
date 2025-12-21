// Amass MCP Server - Fixed Version
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
	log.SetOutput(os.Stderr)
	log.SetPrefix("[MCP] ")

	amassPath := getEnv("AMASS_PATH", "amass")
	engineURL := getEnv("AMASS_ENGINE_URL", "http://localhost:4000/graphql")
	configDir := getEnv("AMASS_CONFIG_DIR", "")

	log.Println("Starting Amass MCP Server...")

	cliWrapper := cli.NewWrapper(amassPath)
	graphqlClient := graphql.NewClient(engineURL)
	engineManager := engine.NewManager(amassPath, engineURL, 30*time.Second, 5*time.Second)
	configManager := config.NewManager(configDir)
	toolsHandler := tools.NewHandler(cliWrapper, graphqlClient, engineManager, configManager)

	server := &MCPServer{handler: toolsHandler}

	log.Println("Server started, waiting for requests...")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		response := server.HandleRequest([]byte(line))
		fmt.Println(string(response))
	}

	engineManager.Cleanup()
}

type MCPServer struct {
	handler *tools.Handler
}

func (s *MCPServer) HandleRequest(data []byte) []byte {
	var req map[string]interface{}
	if err := json.Unmarshal(data, &req); err != nil {
		return s.errorResponse(nil, -32700, "Parse error")
	}

	method, _ := req["method"].(string)
	id := req["id"]

	switch method {
	case "initialize":
		return s.successResponse(id, map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "amass-mcp-server",
				"version": "1.0.0",
			},
		})

	case "tools/list":
		return s.successResponse(id, map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{
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
								"description": "Use passive-only enumeration",
							},
							"brute_force": map[string]interface{}{
								"type":        "boolean",
								"description": "Enable brute force techniques",
							},
						},
						"required": []interface{}{"domain"},
					},
				},
				map[string]interface{}{
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
						"required": []interface{}{"domain"},
					},
				},
				map[string]interface{}{
					"name":        "amass_engine_status",
					"description": "Check if the Amass engine is running and query its status",
					"inputSchema": map[string]interface{}{
						"type":       "object",
						"properties": map[string]interface{}{},
					},
				},
			},
		})

	case "tools/call":
		params, _ := req["params"].(map[string]interface{})
		name, _ := params["name"].(string)
		args, _ := params["arguments"].(map[string]interface{})

		result, err := s.executeTool(name, args)
		if err != nil {
			return s.errorResponse(id, -32000, err.Error())
		}

		return s.successResponse(id, map[string]interface{}{
			"content": []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": result,
				},
			},
		})

	default:
		return s.errorResponse(id, -32601, "Method not found")
	}
}

func (s *MCPServer) executeTool(name string, args map[string]interface{}) (string, error) {
	ctx := context.Background()

	switch name {
	case "amass_enumerate_domain":
		var input types.EnumerateDomainInput
		data, _ := json.Marshal(args)
		json.Unmarshal(data, &input)

		token, err := s.handler.EnumerateDomain(ctx, input)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Enumeration started for %s\nSession Token: %s\n\nThe enumeration is running in the background. Progress updates will be shown in the logs.\n\nUse amass_list_subdomains to retrieve results when complete.", input.Domain, token), nil

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

func (s *MCPServer) successResponse(id interface{}, result interface{}) []byte {
	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}
	data, _ := json.Marshal(response)
	return data
}

func (s *MCPServer) errorResponse(id interface{}, code int, message string) []byte {
	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}
	data, _ := json.Marshal(response)
	return data
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
