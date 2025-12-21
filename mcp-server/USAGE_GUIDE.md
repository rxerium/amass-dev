# Amass MCP Server - Usage Guide

## 🚀 Quick Start

The Amass MCP server is now built and ready to use!

Binary location: `/Users/rxerium/Documents/amass-dev/mcp-server/amass-mcp-server`

## Method 1: Test the Server Manually

### Step 1: Test if the server starts

```bash
cd /Users/rxerium/Documents/amass-dev/mcp-server
./amass-mcp-server
```

The server will start and wait for MCP protocol requests on stdin. You should see:
```
[MCP] Starting Amass MCP Server...
[MCP] Amass path: amass
[MCP] Engine URL: http://localhost:4000/graphql
[MCP] Server started, waiting for requests...
```

### Step 2: Send a test request

Open another terminal and test the server:

```bash
# Send an initialize request
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | ./amass-mcp-server
```

You should get a response like:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {"tools": {}},
    "serverInfo": {"name": "amass-mcp-server", "version": "1.0.0"}
  }
}
```

### Step 3: List available tools

```bash
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | ./amass-mcp-server
```

You should see the 3 available tools:
- `amass_enumerate_domain`
- `amass_list_subdomains`
- `amass_engine_status`

## Method 2: Integrate with Claude Desktop

### Step 1: Configure Claude Desktop

Edit your Claude Desktop config file:

```bash
# Open the config file
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

Add this configuration:

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

### Step 2: Restart Claude Desktop

1. Quit Claude Desktop completely
2. Relaunch Claude Desktop
3. The Amass MCP server will now be available!

### Step 3: Use Amass in Claude

Once integrated, you can use these commands in Claude:

#### Check Engine Status
```
Check the Amass engine status
```

Claude will call: `amass_engine_status`

#### Enumerate a Domain
```
Enumerate subdomains for example.com using Amass
```

Claude will call: `amass_enumerate_domain` with domain="example.com"

#### List Subdomains
```
List all subdomains for example.com with IP addresses
```

Claude will call: `amass_list_subdomains` with domain="example.com" and show_ips=true

## Method 3: Manual Testing with JSON

### Test engine status

```bash
cat <<'EOF' | ./amass-mcp-server
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"amass_engine_status","arguments":{}}}
EOF
```

### Test listing subdomains

First, you need to have some data in your Amass database. If you've run Amass before:

```bash
cat <<'EOF' | ./amass-mcp-server
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"amass_list_subdomains","arguments":{"domain":"example.com","show_ips":true}}}
EOF
```

### Test enumeration

```bash
cat <<'EOF' | ./amass-mcp-server
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"amass_enumerate_domain","arguments":{"domain":"example.com","passive":false}}}
EOF
```

## Environment Variables

You can customize the server behavior with environment variables:

```bash
# Custom Amass binary path
export AMASS_PATH=/usr/local/bin/amass

# Custom engine URL
export AMASS_ENGINE_URL=http://localhost:4000/graphql

# Custom config directory
export AMASS_CONFIG_DIR=/custom/path

# Run the server
./amass-mcp-server
```

## Real-World Example

### Scenario: Enumerate and list subdomains for a target

1. **Start enumeration** (this will take a few minutes):
```bash
cat <<'EOF' | ./amass-mcp-server
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"amass_enumerate_domain","arguments":{"domain":"owasp.org","passive":false,"brute_force":false}}}
EOF
```

You'll get a response with a session token.

2. **Wait for enumeration to complete** (monitor logs)

3. **List the discovered subdomains**:
```bash
cat <<'EOF' | ./amass-mcp-server
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"amass_list_subdomains","arguments":{"domain":"owasp.org","show_ips":true}}}
EOF
```

## Troubleshooting

### Server won't start

```bash
# Check if Amass is installed
which amass

# Check if port 4000 is available (for engine)
lsof -i :4000

# Run with explicit path
AMASS_PATH=/Users/rxerium/go/bin/amass ./amass-mcp-server
```

### No subdomains returned

Make sure you've run an enumeration first:
```bash
# Run Amass directly to populate the database
amass enum -d example.com

# Then query via MCP
cat <<'EOF' | ./amass-mcp-server
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"amass_list_subdomains","arguments":{"domain":"example.com"}}}
EOF
```

### Engine not starting

The engine will auto-start when needed for enumeration. If you want to start it manually:

```bash
# Start Amass engine in a separate terminal
amass engine

# The MCP server will now connect to it
```

## Advanced Usage

### Create an alias for easy access

Add to your `~/.zshrc` or `~/.bashrc`:

```bash
alias amass-mcp='/Users/rxerium/Documents/amass-dev/mcp-server/amass-mcp-server'
```

Then you can use:
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | amass-mcp
```

### Use with MCP Inspector

The MCP Inspector is a tool for debugging MCP servers:

```bash
# Install MCP Inspector
npm install -g @modelcontextprotocol/inspector

# Run with your server
mcp-inspector /Users/rxerium/Documents/amass-dev/mcp-server/amass-mcp-server
```

## Next Steps

1. ✅ Server is built and ready
2. 📝 Choose your integration method (Claude Desktop or manual)
3. 🔍 Start enumerating domains!
4. 📊 Query your discovered assets

For full Amass documentation, visit: https://github.com/owasp-amass/amass

---

**Happy hunting! 🎯**
