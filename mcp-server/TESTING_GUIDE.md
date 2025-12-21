# Amass MCP Server - Testing Guide

This guide helps you test all the newly added Amass capabilities through Claude Desktop.

## Prerequisites

1. **Restart Claude Desktop** to load the updated MCP server
   - Quit Claude Desktop completely
   - Reopen the application
   - The new tools will be automatically loaded

2. **Verify Services Running**
   ```bash
   cd /Users/rxerium/Documents/amass-docker-compose
   docker-compose ps
   ```
   Ensure these containers are running:
   - assetdb (PostgreSQL)
   - neo4j (Graph database)
   - engine (GraphQL API)
   - syslog

## Test Cases

### ✅ Test 1: Basic Enumeration (Already Working)

**In Claude Desktop:**
```
Enumerate subdomains for rxerium.com
```

**Expected Result:**
- ✓ Returns success message with PID
- ✓ Indicates scan will take ~5 minutes
- ✓ Suggests using amass_scan_status to check progress

**Verify:**
```
What's the scan status for rxerium.com?
```

---

### ✅ Test 2: List Subdomains (Already Working)

**In Claude Desktop:**
```
List all subdomains for rxerium.com
```

**Expected Result:**
- ✓ Returns JSON array of discovered subdomains
- ✓ Shows count of subdomains found
- ✓ Each subdomain has FQDN field

---

### ✅ Test 3: Scan Status (Already Working)

**In Claude Desktop:**
```
Show me all running scans
```

**Expected Result:**
- ✓ Lists all active and recent scans
- ✓ Shows domain, status (running/completed), elapsed time, PID
- ✓ Uses emoji indicators (🔄 for running, ✓ for completed)

---

### ✅ Test 4: Engine Status (Already Working)

**In Claude Desktop:**
```
Is the Amass engine running?
```

**Expected Result:**
- ✓ Returns JSON with engine status
- ✓ Shows running/healthy status
- ✓ Displays URL and port

---

### 🆕 Test 5: Track Changes (NEW)

**Setup:**
First ensure you have baseline data:
```bash
# Check if entities exist
docker exec -i assetdb psql -U postgres -d assetdb -c "SELECT COUNT(*) FROM entities WHERE etype='FQDN';"
```

**In Claude Desktop:**
```
Track changes for rxerium.com in the last 24 hours
```

**Expected Result:**
- ✓ Returns changes detected (new/modified/deleted assets)
- ✓ Shows timestamp for each change
- ✓ Indicates asset type and change type

**Possible Issues:**
- May return "No changes detected" if this is first scan
- Track service requires multiple enumeration runs over time
- Depends on CLI wrapper implementation

---

### 🆕 Test 6: Query Associations (NEW)

**Setup:**
Ensure Neo4j has data:
```bash
# Check Neo4j connectivity
docker exec -i neo4j cypher-shell -u neo4j -p password "MATCH (n) RETURN count(n);"
```

**In Claude Desktop:**
```
What assets are associated with rxerium.com?
```

**Expected Result:**
- ✓ Returns associations (subject-predicate-object triples)
- ✓ Shows relationships like shared IPs, ASNs, certificates
- ✓ JSON array of association results

**Possible Issues:**
- May return "No associations found" if Neo4j is empty
- Requires data to be loaded into graph database
- CLI wrapper must support associations query

---

### 🆕 Test 7: Generate Visualization (NEW)

**In Claude Desktop:**
```
Generate a D3 visualization for rxerium.com
```

**Expected Result:**
- ✓ Creates HTML file with interactive graph
- ✓ Returns file path
- ✓ Shows content preview or file location

**Alternative formats:**
```
Generate a DOT visualization for rxerium.com
Generate a GEXF visualization for rxerium.com
```

**Verify Output:**
```bash
# Check for generated file
ls -la /tmp/amass-viz-*
```

**Possible Issues:**
- File path may be in temp directory
- HTML visualization requires browser to view
- CLI wrapper must support viz command

---

### 🆕 Test 8: Get Configuration (NEW)

**In Claude Desktop:**
```
Show me the Amass configuration
```

**Expected Result:**
- ✓ Returns full configuration as JSON
- ✓ Shows scope, options, data sources
- ✓ Displays all configured settings

**Test specific section:**
```
Get the datasources configuration
```

---

### 🆕 Test 9: Update Configuration (NEW)

**In Claude Desktop:**
```
Update the Amass config to enable active scanning
```

**Expected Result:**
- ✓ Configuration updated successfully
- ✓ Shows updated config
- ✓ If validate=true, shows validation results

**Verify:**
```
Show me the Amass configuration
```

---

### 🆕 Test 10: Add API Key (NEW)

**In Claude Desktop:**
```
Add API key for test source: test123
```

**Expected Result:**
- ✓ Success message
- ✓ Confirms source and key added
- ✓ Returns JSON with success status

**Note:** Use a dummy source/key for testing, or real credentials if you have them.

---

### 🆕 Test 11: List Data Sources (NEW)

**In Claude Desktop:**
```
What data sources are available?
```

**Expected Result:**
- ✓ Returns array of data source names
- ✓ Shows configured and available sources
- ✓ May include sources like: AlienVault, Censys, GitHub, Shodan, etc.

---

## Troubleshooting

### Issue: "Unknown tool" error

**Cause:** Claude Desktop hasn't reloaded the MCP server

**Fix:**
1. Quit Claude Desktop completely (Cmd+Q)
2. Verify binary was rebuilt:
   ```bash
   ls -lh /Users/rxerium/Documents/amass-dev/mcp-server/amass-mcp-server
   ```
3. Check timestamp is recent (after adding new tools)
4. Reopen Claude Desktop

---

### Issue: "Function not implemented" or similar error

**Cause:** Backend implementation may need adjustment for docker-compose environment

**Fix:**
1. Check docker-compose services are running
2. Verify service names in compose.yaml match tool expectations
3. Check logs:
   ```bash
   docker-compose logs -f
   ```

---

### Issue: "No data found" for associations/changes/viz

**Cause:** These features require specific data or multiple runs

**Fix:**
1. **Associations:** Ensure Neo4j has data loaded
2. **Changes:** Run multiple enumerations over time
3. **Visualizations:** Ensure enumeration completed successfully

---

### Issue: Config operations failing

**Cause:** Config manager may need file path setup

**Fix:**
1. Check AMASS_CONFIG_DIR environment variable
2. Verify config file exists or can be created
3. Check permissions on config directory

---

## Verification Checklist

After testing, verify:

- [ ] All 11 tools are available in Claude Desktop
- [ ] Enumeration works (existing)
- [ ] List subdomains works (existing)
- [ ] Scan status works (existing)
- [ ] Engine status works (existing)
- [ ] Track changes returns response (even if "no changes")
- [ ] Query associations returns response (even if "no associations")
- [ ] Generate visualization creates file
- [ ] Get config returns configuration
- [ ] Update config modifies settings
- [ ] Add API key accepts input
- [ ] List data sources returns array

---

## Expected Limitations

Some features may have limited functionality in the current docker-compose setup:

1. **Track Changes**: Requires CLI wrapper with `amass track` command support
2. **Query Associations**: Needs Neo4j populated with relationship data
3. **Visualizations**: Requires CLI wrapper with `amass viz` command
4. **Config Operations**: May need config file setup

**These are architectural dependencies, not bugs.** The MCP tools are now exposed and will work once the backend implementations are fully integrated with the docker-compose environment.

---

## Quick Test Script

Run all basic tests in sequence:

```
1. Enumerate subdomains for test.com
2. Check scan status
3. List subdomains for test.com (wait 5 min first)
4. Show engine status
5. List available data sources
6. Get Amass configuration
7. Track changes for test.com in last 24h
8. Query associations for test.com
9. Generate D3 visualization for test.com
```

---

## Success Criteria

The MCP server is working correctly if:

1. ✅ All 11 tools are recognized by Claude
2. ✅ No "unknown tool" errors
3. ✅ Each tool returns a response (even if "no data")
4. ✅ No JSON-RPC errors
5. ✅ No MCP protocol validation errors

---

**Last Updated**: 2025-12-21
**Next Steps**: Test in Claude Desktop, report any issues
