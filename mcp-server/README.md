# Amass MCP Server (Go)

A Model Context Protocol (MCP) server for OWASP Amass written in Go. This server exposes subdomain enumeration, asset tracking, visualization, and configuration management capabilities to Claude and other MCP clients.

## Overview

This MCP server provides a comprehensive interface to OWASP Amass, allowing you to:

- 🔍 **Enumerate subdomains** with real-time progress tracking
- 📊 **Query discovered assets** from the Amass database
- 📈 **Track changes** in your attack surface over time
- 🗺️ **Generate visualizations** (D3, DOT, GEXF formats)
- ⚙️ **Manage configuration** and API keys for 40+ data sources

## Architecture

The MCP server uses a **hybrid approach**:

- **CLI wrapper** for simple operations (list subdomains, track changes, visualizations)
- **GraphQL client** for complex operations (enumeration with real-time progress)
- **Engine lifecycle management** automatically starts/stops the Amass engine as needed

## Installation

### Prerequisites

1. **Go 1.24+** installed
2. **OWASP Amass v5.0.0+** installed and in PATH
   - Install from: https://github.com/owasp-amass/amass
   - Or use: `brew install amass` (macOS)

### Building

```bash
# Navigate to the MCP server directory
cd /Users/rxerium/Documents/amass-dev/mcp-server

# Download dependencies
go mod download

# Build the binary
go build -o amass-mcp-server ./cmd/mcp-server

# Or install it
go install ./cmd/mcp-server
```

## Configuration

### Environment Variables

Set these environment variables to customize behavior:

```bash
export AMASS_PATH=/usr/local/bin/amass  # Path to amass binary
export AMASS_ENGINE_URL=http://localhost:4000/graphql  # GraphQL endpoint
export AMASS_CONFIG_DIR=~/.config/amass  # Config directory
```

### MCP Client Configuration

#### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "amass": {
      "command": "/Users/rxerium/Documents/amass-dev/mcp-server/amass-mcp-server",
      "args": [],
      "env": {}
    }
  }
}
```

#### Other MCP Clients

Use the same command pattern with stdio transport:

```bash
/Users/rxerium/Documents/amass-dev/mcp-server/amass-mcp-server
```

## Available Tools

### 1. amass_enumerate_domain

Perform subdomain enumeration with real-time progress tracking.

**Example:**
```
Use amass_enumerate_domain with domain="example.com" and brute_force=true
```

### 2. amass_list_subdomains

List all discovered subdomains from the database.

**Example:**
```
Use amass_list_subdomains with domain="example.com" and show_ips=true
```

### 3. amass_track_changes

Track changes in discovered assets since a specific time.

**Example:**
```
Use amass_track_changes with domain="example.com" and since="12/19 00:00:00 2024 UTC"
```

### 4. amass_query_associations

Query asset associations using graph traversal.

**Example:**
```
Use amass_query_associations with domain="example.com"
```

### 5. amass_generate_visualization

Generate network visualizations.

**Formats:**
- `d3` - Interactive HTML visualization
- `dot` - Graphviz DOT format
- `gexf` - Gephi format

**Example:**
```
Use amass_generate_visualization with domain="example.com" and format="d3"
```

### 6. amass_get_config

Read current Amass configuration.

**Example:**
```
Use amass_get_config to view the current configuration
```

### 7. amass_update_config

Update Amass configuration.

**Example:**
```
Use amass_update_config to add a domain to the scope
```

### 8. amass_add_api_key

Add or update API key for a data source.

**Example:**
```
Use amass_add_api_key with source="virustotal" and api_key="abc123"
```

### 9. amass_engine_status

Check if the Amass engine is running.

**Example:**
```
Use amass_engine_status to check engine status
```

### 10. amass_list_data_sources

List all configured data sources.

**Example:**
```
Use amass_list_data_sources to see configured data sources
```

## Project Structure

```
mcp-server/
├── cmd/
│   └── mcp-server/
│       └── main.go              # MCP server entry point
├── internal/
│   ├── types/
│   │   └── types.go             # Type definitions
│   ├── engine/
│   │   └── manager.go           # Engine lifecycle management
│   ├── config/
│   │   └── manager.go           # Configuration management
│   ├── cli/
│   │   └── wrapper.go           # CLI command wrapper
│   ├── graphql/
│   │   └── client.go            # GraphQL client
│   └── tools/
│       └── tools.go             # MCP tool implementations
├── go.mod                       # Go module definition
└── README.md                    # This file
```

## Development

### Running Tests

```bash
go test ./...
```

### Building for Release

```bash
# Build for current platform
go build -o amass-mcp-server ./cmd/mcp-server

# Build for multiple platforms
GOOS=linux GOARCH=amd64 go build -o amass-mcp-server-linux ./cmd/mcp-server
GOOS=darwin GOARCH=arm64 go build -o amass-mcp-server-darwin-arm64 ./cmd/mcp-server
GOOS=windows GOARCH=amd64 go build -o amass-mcp-server.exe ./cmd/mcp-server
```

## Usage Examples

### Basic Subdomain Enumeration

1. Start enumeration:
```
Use amass_enumerate_domain with domain="example.com"
```

2. Check progress in logs (automatically shown)

3. List results when complete:
```
Use amass_list_subdomains with domain="example.com" and show_ips=true
```

### Continuous Monitoring

1. Run initial enumeration:
```
Use amass_enumerate_domain with domain="example.com"
```

2. Track changes since last week:
```
Use amass_track_changes with domain="example.com" and since="12/13 00:00:00 2024 UTC"
```

### Advanced Enumeration

```
Use amass_enumerate_domain with:
- domain="example.com"
- brute_force=true
- alterations=true
- timeout_minutes=30
```

## Troubleshooting

### Amass not found

```bash
# Check if Amass is in PATH
which amass

# Set custom path
export AMASS_PATH=/usr/local/bin/amass
```

### Engine fails to start

```bash
# Check if port 4000 is available
lsof -i :4000

# Manually start engine
amass engine
```

### Build errors

```bash
# Clean module cache
go clean -modcache

# Re-download dependencies
go mod download
go mod tidy
```

## Contributing

This MCP server is part of the OWASP Amass project. Contributions are welcome!

## License

Apache License 2.0 - See the main Amass repository for details.

## Links

- **OWASP Amass**: https://github.com/owasp-amass/amass
- **MCP Protocol**: https://modelcontextprotocol.io
- **MCP Go SDK**: https://github.com/mark3labs/mcp-go
- **Claude Desktop**: https://claude.ai

---

**Built with ❤️ for the OWASP Amass Project**
