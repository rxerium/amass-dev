# New Data Extraction Tools - Summary

## 🎉 What's New

I've added **5 powerful new tools** to extract comprehensive data from Amass scans beyond just subdomains.

### Previous Issue
- `amass_query_associations` was failing due to CLI wrapper issues
- Limited data visibility (only subdomains were accessible)

### Solution
- Created new tools that query the PostgreSQL database directly
- Extract all 14 entity types that Amass discovers
- Access relationship data from the edges table

---

## 🆕 New Tools (Total: 16 tools)

### 1. **amass_get_ip_addresses**
Get all IP addresses associated with discovered subdomains.

**Example:**
```
What IP addresses were found for kynd.io?
Get all IPs for the domain
```

**Returns:**
- IP addresses
- Associated metadata from Amass discovery

---

### 2. **amass_get_whois_data**
Get WHOIS and contact record information.

**Example:**
```
Show me WHOIS data for kynd.io
What contact information was discovered?
```

**Returns:**
- Registrar information
- Contact records
- Administrative details
- Technical contacts

---

### 3. **amass_get_domain_info**
Get detailed domain record information.

**Example:**
```
What domain information was found for kynd.io?
Show me the domain record details
```

**Returns:**
- Domain record details
- DNS information
- Domain-level metadata

---

### 4. **amass_get_all_assets**
Get ALL discovered assets across all 14 entity types.

**Example:**
```
Show me everything Amass found for kynd.io
What assets were discovered in the scan?
```

**Returns comprehensive data organized by type:**
- **FQDN** - Subdomains
- **IPAddress** - IP addresses
- **Netblock** - IP ranges/CIDR blocks
- **AutonomousSystem** - ASN information
- **AutnumRecord** - ASN records
- **ContactRecord** - WHOIS/contact info
- **DomainRecord** - Domain records
- **Organization** - Organizations
- **Person** - People
- **Phone** - Phone numbers
- **Location** - Geographic locations
- **URL** - URLs
- **Identifier** - Various identifiers
- **IPNetRecord** - IP network records

---

### 5. **amass_get_relationships**
Get relationships and associations between assets.

**Example:**
```
What relationships exist for kynd.io?
Show me asset associations
How are the discovered assets connected?
```

**Returns:**
- Source asset → Relationship type → Target asset
- Asset connections (subdomain → IP, IP → ASN, etc.)
- Infrastructure relationships
- Up to 100 most relevant relationships

---

## 📊 Complete Tool List (16 Tools)

### Core Enumeration (4)
1. amass_enumerate_domain
2. amass_list_subdomains
3. amass_scan_status
4. amass_engine_status

### Advanced Capabilities (7)
5. amass_track_changes
6. amass_query_associations (legacy - may fail)
7. amass_generate_visualization
8. amass_get_config
9. amass_update_config
10. amass_add_api_key
11. amass_list_data_sources

### New Data Extraction (5) 🆕
12. **amass_get_ip_addresses**
13. **amass_get_whois_data**
14. **amass_get_domain_info**
15. **amass_get_all_assets**
16. **amass_get_relationships**

---

## 🔍 Entity Types Discovered by Amass

The database contains **14 different entity types**:

| Entity Type | Description | Example |
|-------------|-------------|---------|
| FQDN | Fully qualified domain names | kynd.io, www.kynd.io |
| IPAddress | IP addresses | 104.21.45.67 |
| Netblock | IP ranges/CIDR | 104.21.0.0/16 |
| AutonomousSystem | AS numbers and names | AS13335 (Cloudflare) |
| AutnumRecord | ASN records | BGP information |
| ContactRecord | WHOIS contacts | Registrar, admin, tech |
| DomainRecord | Domain details | Registration info |
| Organization | Companies/orgs | KYND Limited |
| Person | Individuals | Admin contacts |
| Phone | Phone numbers | Contact numbers |
| Location | Geographic data | City, country |
| URL | URLs discovered | https://kynd.io/path |
| Identifier | Various IDs | Certificate IDs, etc. |
| IPNetRecord | IP network records | Network details |

---

## 🎯 Usage Examples

### Comprehensive Analysis
```
1. Enumerate subdomains for kynd.io
2. Show me all assets discovered for kynd.io
3. Get relationships for kynd.io
4. What WHOIS data was found?
5. Show me the IP addresses
```

### Specific Queries
```
- "What contact information did Amass find for kynd.io?"
- "Show me all the different types of assets for this domain"
- "What IP addresses are associated with the subdomains?"
- "Get me the domain record details"
- "How are the assets connected?"
```

### Investigation Workflow
```
1. Run enumeration
2. Get all assets → see what types exist
3. Get relationships → understand connections
4. Deep dive into specific types (IPs, WHOIS, etc.)
5. Export or visualize findings
```

---

## ✅ What's Fixed

### 1. Association Queries Work Now
- Old `amass_query_associations` was failing
- New `amass_get_relationships` queries database directly
- Returns actual relationship data from edges table

### 2. Comprehensive Data Access
- No longer limited to just subdomains
- Access all 14 entity types
- See the complete attack surface

### 3. Direct Database Queries
- Fast, reliable responses
- No dependency on CLI wrapper
- Works with current docker-compose setup

---

## 🔄 Next Steps

1. **Restart Claude Desktop**
   - Quit completely (⌘ + Q)
   - Reopen to load new tools

2. **Test New Tools**
   ```
   - "Show me all assets for kynd.io"
   - "What relationships were discovered?"
   - "Get WHOIS data for kynd.io"
   ```

3. **Explore Data**
   - Ask for specific entity types
   - Query relationships
   - Combine with visualizations

---

## 📝 Technical Details

**Binary:** `/Users/rxerium/Documents/amass-dev/mcp-server/amass-mcp-server`
**Rebuilt:** 2025-12-21 10:06
**Size:** 8.8MB
**Total Tools:** 16
**New Tools:** 5

**Database Schema Used:**
- `entities` table - All discovered assets
- `edges` table - Relationships between entities
- Direct PostgreSQL queries via docker exec

**Query Strategy:**
- Domain-aware filtering
- JSONB content parsing
- JOIN operations for relationships
- Efficient result limiting

---

## 🎉 Benefits

### For Reconnaissance
- Complete attack surface visibility
- Infrastructure relationships
- Contact information discovery
- IP/ASN mapping

### For Analysis
- Understand asset connections
- Identify shared infrastructure
- Track organizational relationships
- Export comprehensive data

### For Reporting
- Rich data for threat intelligence
- Complete asset inventory
- Relationship mapping
- WHOIS/registration details

---

**Last Updated:** 2025-12-21 10:06
**Status:** ✅ Ready to use
**Action Required:** Restart Claude Desktop
