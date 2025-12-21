# Amass MCP Server - Quick Start Guide

## 🚀 Get Started in 3 Steps

### Step 1: Restart Claude Desktop
The MCP server has been updated with 7 new tools. Restart Claude to load them:

1. **Quit Claude Desktop completely** (⌘ + Q on Mac)
2. **Reopen Claude Desktop**
3. The updated MCP server loads automatically

### Step 2: Verify Services Running
Ensure Docker Compose services are up:

```bash
cd /Users/rxerium/Documents/amass-docker-compose
docker-compose ps
```

**Required containers:**
- ✅ assetdb (PostgreSQL)
- ✅ neo4j (Graph database)
- ✅ engine (GraphQL API)
- ✅ syslog

If not running:
```bash
docker-compose up -d
```

### Step 3: Test in Claude Desktop

Try these commands in order:

#### 1️⃣ Basic Enumeration
```
Enumerate subdomains for rxerium.com
```

#### 2️⃣ Check Status
```
What's the scan status?
```

#### 3️⃣ List Results (wait 5 minutes first)
```
List all subdomains for rxerium.com
```

#### 4️⃣ Try New Features
```
What data sources are available?
Show me the Amass configuration
Query associations for rxerium.com
Generate a D3 visualization for rxerium.com
```

---

## 🎯 What You Can Ask Claude

### Discovery
- "Enumerate subdomains for example.com"
- "Find all subdomains of hackthebox.com"
- "Run a passive scan on target.com"

### Monitoring
- "What's the scan status?"
- "Is the Amass engine running?"
- "Show me all active scans"

### Analysis
- "What assets are associated with example.com?"
- "Track changes for example.com in the last 24 hours"
- "Generate a network visualization"

### Configuration
- "Show me the configuration"
- "List available data sources"
- "Add my SecurityTrails API key: [key]"

---

## 📚 Documentation

- **AMASS_TOOLS_REFERENCE.md** - Complete tool reference (all 11 tools)
- **TESTING_GUIDE.md** - Comprehensive testing guide
- **IMPLEMENTATION_SUMMARY.md** - Technical implementation details

---

## ⚡ Quick Test Script

Run these in sequence to test all features:

```
1. Enumerate subdomains for test.com
2. Check scan status
3. Show engine status
4. List data sources
5. Get configuration
6. List subdomains for test.com (after 5 min)
7. Query associations for test.com
8. Generate D3 visualization for test.com
9. Track changes for test.com in last 24h
```

---

## 🛠️ Troubleshooting

### Issue: Claude says "unknown tool"
**Fix:** Restart Claude Desktop (must quit completely, not just close window)

### Issue: "No data found"
**Fix:**
- For subdomains: Wait for enumeration to complete (~5 min)
- For associations: Ensure Neo4j has data
- For changes: Requires multiple scans over time

### Issue: Docker services not running
**Fix:**
```bash
cd /Users/rxerium/Documents/amass-docker-compose
docker-compose down
docker-compose up -d
docker-compose ps  # Verify all running
```

---

## ✅ Success Indicators

You'll know it's working when:
- ✅ No "unknown tool" errors
- ✅ Enumeration starts successfully
- ✅ Scan status shows running/completed scans
- ✅ List subdomains returns results
- ✅ All 11 tools are recognized by Claude

---

## 📊 Full Tool List

Now available in Claude:

1. **amass_enumerate_domain** - Start subdomain enumeration
2. **amass_list_subdomains** - List discovered subdomains
3. **amass_scan_status** - Check scan progress
4. **amass_engine_status** - Check engine health
5. **amass_track_changes** 🆕 - Monitor infrastructure changes
6. **amass_query_associations** 🆕 - Discover asset relationships
7. **amass_generate_visualization** 🆕 - Create network graphs
8. **amass_get_config** 🆕 - Retrieve configuration
9. **amass_update_config** 🆕 - Modify settings
10. **amass_add_api_key** 🆕 - Configure data sources
11. **amass_list_data_sources** 🆕 - List available sources

---

## 🎉 You're Ready!

Open Claude Desktop and start exploring. You now have full Amass capabilities through natural language.

**Pro tip:** Start with basic enumeration, then explore advanced features like associations and visualizations once you have data.

---

**Need Help?**
- Check TESTING_GUIDE.md for detailed test cases
- See AMASS_TOOLS_REFERENCE.md for complete documentation
- Review IMPLEMENTATION_SUMMARY.md for technical details

**Last Updated**: 2025-12-21
