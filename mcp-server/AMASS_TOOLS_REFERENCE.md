# Amass MCP Server - Complete Tool Reference

This MCP server exposes the full power of OWASP Amass through Claude. You can now perform comprehensive attack surface mapping and reconnaissance directly through natural language queries.

## Available Tools

### 1. amass_enumerate_domain
**Start subdomain enumeration for a target domain**

Start a comprehensive subdomain enumeration scan. The scan runs in the background (~5 minutes) and stores results in the PostgreSQL database.

**Parameters:**
- `domain` (required): Target domain (e.g., example.com)
- `passive` (optional): Use passive-only enumeration (no active probing)

**Example queries:**
- "Enumerate subdomains for rxerium.com"
- "Start a passive scan of example.com"
- "Discover all subdomains of hackthebox.com"

---

### 2. amass_list_subdomains
**List discovered subdomains from enumeration**

Query the database for all discovered subdomains. Can query by domain or session token.

**Parameters:**
- `domain` (required): Domain to query
- `session_token` (optional): Specific session token to query
- `show_ips` (optional): Include IP addresses in results

**Example queries:**
- "List all subdomains for rxerium.com"
- "Show me the enumeration results for example.com"
- "What subdomains did you find for hackthebox.com?"

---

### 3. amass_scan_status
**Check enumeration scan status**

Monitor running and completed scans. Shows PID, elapsed time, and completion status.

**Parameters:**
- `domain` (optional): Specific domain to check (omit to see all scans)

**Example queries:**
- "What's the status of the rxerium.com scan?"
- "Show me all running scans"
- "Is the enumeration finished?"

---

### 4. amass_engine_status
**Check Amass engine status**

Verify that the Amass GraphQL engine and supporting services are running.

**Example queries:**
- "Is the Amass engine running?"
- "Check engine status"
- "What's the engine health?"

---

### 5. amass_track_changes
**Track changes in discovered assets over time**

Monitor infrastructure changes by comparing enumeration results across different time periods. Detects new, modified, or deleted assets.

**Parameters:**
- `domain` (required): Domain to track
- `since` (required): Time period (e.g., '24h', '7d', '30d')

**Example queries:**
- "What changed in the last 24 hours for rxerium.com?"
- "Track changes for example.com in the last week"
- "Show me new subdomains discovered in the last 7 days"

---

### 6. amass_query_associations
**Query asset associations and relationships**

Discover related infrastructure through graph traversal. Find domains on the same IP, shared ASNs, certificate relationships, and more.

**Parameters:**
- `domain` (required): Domain to query
- `walk_pattern` (optional): Graph traversal pattern

**Example queries:**
- "What assets are associated with rxerium.com?"
- "Find all domains on the same IP as example.com"
- "Show me infrastructure relationships for hackthebox.com"

---

### 7. amass_generate_visualization
**Generate network visualizations**

Create visual representations of discovered infrastructure and relationships.

**Parameters:**
- `domain` (required): Domain to visualize
- `format` (required): Output format - 'd3' (interactive HTML), 'dot' (Graphviz), or 'gexf'
- `output_path` (optional): Custom output file path

**Example queries:**
- "Generate a D3 visualization for rxerium.com"
- "Create a network graph for example.com in DOT format"
- "Visualize the infrastructure for hackthebox.com"

---

### 8. amass_get_config
**Get Amass configuration**

Retrieve current Amass configuration settings. Can get full config or specific sections.

**Parameters:**
- `section` (optional): Specific section (e.g., 'scope', 'datasources', 'options')

**Example queries:**
- "Show me the Amass configuration"
- "What data sources are configured?"
- "Get the scope configuration"

---

### 9. amass_update_config
**Update Amass configuration**

Modify configuration settings including scope, options, data sources, and more.

**Parameters:**
- `updates` (required): Configuration updates as key-value pairs
- `validate` (optional): Validate configuration after update

**Example queries:**
- "Update the Amass config to use active scanning"
- "Enable brute force in the configuration"
- "Add example.com to the scope"

---

### 10. amass_add_api_key
**Add API keys for data sources**

Configure API keys for premium data sources like SecurityTrails, Shodan, VirusTotal, etc. This significantly increases enumeration coverage.

**Parameters:**
- `source` (required): Data source name (e.g., 'SecurityTrails', 'Shodan', 'VirusTotal')
- `api_key` (required): API key for the source
- `additional_config` (optional): Additional source-specific configuration

**Example queries:**
- "Add my SecurityTrails API key: abc123..."
- "Configure Shodan with API key xyz789..."
- "Set up VirusTotal API access"

**Supported Data Sources:**
- SecurityTrails
- Shodan
- Censys
- VirusTotal
- PassiveTotal
- URLScan
- GitHub
- And 50+ more sources

---

### 11. amass_list_data_sources
**List available data sources**

Display all configured and available data sources. Shows which services are active.

**Example queries:**
- "What data sources are available?"
- "List all configured API integrations"
- "Show me the active data sources"

---

## Complete Capabilities

With these tools, you can perform:

### 🔍 **Reconnaissance & Discovery**
- Subdomain enumeration (passive & active)
- DNS record discovery
- IP address mapping
- ASN identification
- Certificate transparency monitoring

### 🕸️ **Infrastructure Mapping**
- Asset associations
- Shared infrastructure detection
- Network relationship analysis
- Certificate chain analysis

### 📊 **Monitoring & Tracking**
- Change detection over time
- New asset discovery
- Infrastructure modifications
- Deleted resource tracking

### 📈 **Visualization & Reporting**
- Interactive D3.js graphs
- Graphviz DOT diagrams
- GEXF network files
- Comprehensive JSON exports

### ⚙️ **Configuration & Integration**
- Custom scope definition
- API key management
- Data source configuration
- Scan option customization

---

## Example Workflows

### Basic Enumeration
```
1. "Enumerate subdomains for example.com"
2. Wait ~5 minutes or check: "What's the scan status?"
3. "List all subdomains for example.com"
4. "Generate a D3 visualization for example.com"
```

### Infrastructure Analysis
```
1. "List subdomains for example.com"
2. "Query associations for example.com"
3. "Show me all domains on the same IP"
4. "Generate a network visualization"
```

### Continuous Monitoring
```
1. "Enumerate subdomains for example.com" (run daily)
2. "Track changes for example.com in the last 24h"
3. "Show me new subdomains discovered today"
```

### Advanced Configuration
```
1. "List available data sources"
2. "Add my SecurityTrails API key: [key]"
3. "Update config to enable brute force"
4. "Enumerate example.com with enhanced sources"
```

---

## Notes

- **Scan Duration**: Full enumeration typically takes 5 minutes with default timeout
- **Background Execution**: Scans run in the background, so you can continue chatting
- **Status Tracking**: Use `amass_scan_status` to monitor progress
- **Database Persistence**: All results are stored in PostgreSQL for future queries
- **API Keys**: Adding API keys significantly increases discovery coverage

---

## Technical Details

- **Database**: PostgreSQL (assetdb container on port 55432)
- **Engine**: GraphQL API (localhost:4000)
- **Graph DB**: Neo4j for relationship analysis
- **Execution**: Docker Compose orchestration
- **Protocol**: MCP (Model Context Protocol) over JSON-RPC 2.0

---

**Last Updated**: 2025-12-21
**MCP Server Version**: 1.0.0
**Amass Branch**: mcp
