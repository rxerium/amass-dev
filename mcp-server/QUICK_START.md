# Amass MCP Server - Quick Start

## ✅ Your Server is Ready!

Location: `/Users/rxerium/Documents/amass-dev/mcp-server/amass-mcp-server`
Size: 8.6MB
Status: ✅ Tested and working

## 🎯 3 Ways to Use It

### 1️⃣  Use with Claude Desktop (Recommended)

**Setup (one-time):**

```bash
# Edit Claude Desktop config
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**Add this:**
```json
{
  "mcpServers": {
    "amass": {
      "command": "/Users/rxerium/Documents/amass-dev/mcp-server/amass-mcp-server"
    }
  }
}
```

**Restart Claude Desktop**, then use these commands:

```
Check the Amass engine status

Enumerate subdomains for example.com

List all subdomains for owasp.org with IPs
```

---

### 2️⃣  Test Manually (CLI)

**Check engine status:**
```bash
cd /Users/rxerium/Documents/amass-dev/mcp-server

echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"amass_engine_status","arguments":{}}}' | ./amass-mcp-server
```

**List subdomains:**
```bash
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"amass_list_subdomains","arguments":{"domain":"example.com","show_ips":true}}}' | ./amass-mcp-server
```

**Start enumeration:**
```bash
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"amass_enumerate_domain","arguments":{"domain":"example.com"}}}' | ./amass-mcp-server
```

---

### 3️⃣  Run with MCP Inspector (Debug)

```bash
# Install MCP Inspector
npm install -g @modelcontextprotocol/inspector

# Run
mcp-inspector /Users/rxerium/Documents/amass-dev/mcp-server/amass-mcp-server
```

## 🔧 Available Tools

| Tool | Description |
|------|-------------|
| `amass_enumerate_domain` | Start subdomain enumeration |
| `amass_list_subdomains` | List discovered subdomains |
| `amass_engine_status` | Check if engine is running |

## 📝 Example Workflow

### Discover subdomains for a target:

1. **Start enumeration** (takes a few minutes):
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"amass_enumerate_domain","arguments":{"domain":"owasp.org"}}}' | ./amass-mcp-server
```

2. **Wait for completion** (watch the logs)

3. **List results**:
```bash
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"amass_list_subdomains","arguments":{"domain":"owasp.org","show_ips":true}}}' | ./amass-mcp-server
```

## 🐛 Troubleshooting

**Amass not found?**
```bash
export AMASS_PATH=/Users/rxerium/go/bin/amass
./amass-mcp-server
```

**No data returned?**
```bash
# Run Amass directly first to populate the database
amass enum -d example.com

# Then query via MCP
```

## 📚 Full Documentation

- **Usage Guide**: `USAGE_GUIDE.md`
- **README**: `README.md`
- **Amass Docs**: https://github.com/owasp-amass/amass

---

**🎉 You're all set! Start with Method 1 (Claude Desktop) for the best experience.**
