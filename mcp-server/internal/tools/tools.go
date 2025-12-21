// Package tools implements all MCP tools for Amass
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/owasp-amass/amass/mcp-server/internal/cli"
	"github.com/owasp-amass/amass/mcp-server/internal/config"
	"github.com/owasp-amass/amass/mcp-server/internal/engine"
	"github.com/owasp-amass/amass/mcp-server/internal/graphql"
	"github.com/owasp-amass/amass/mcp-server/internal/types"
)

// EnumStatus tracks running enumeration status
type EnumStatus struct {
	Domain        string
	StartTime     time.Time
	PID           int
	Passive       bool
	Running       bool
	ContainerName string
}

// Handler handles all MCP tool requests
type Handler struct {
	cliWrapper    *cli.Wrapper
	graphqlClient *graphql.Client
	engineManager *engine.Manager
	configManager *config.Manager
	activeScans   map[string]*EnumStatus
}

// NewHandler creates a new tools handler
func NewHandler(
	cliWrapper *cli.Wrapper,
	graphqlClient *graphql.Client,
	engineManager *engine.Manager,
	configManager *config.Manager,
) *Handler {
	return &Handler{
		cliWrapper:    cliWrapper,
		graphqlClient: graphqlClient,
		engineManager: engineManager,
		configManager: configManager,
		activeScans:   make(map[string]*EnumStatus),
	}
}

// EnumerateDomain starts domain enumeration
func (h *Handler) EnumerateDomain(ctx context.Context, input types.EnumerateDomainInput) (string, error) {
	log.Printf("[Tools] Starting enumeration for %s\n", input.Domain)

	// Ensure engine is running
	if err := h.engineManager.EnsureEngine(ctx); err != nil {
		return "", fmt.Errorf("failed to start engine: %w", err)
	}

	// Build configuration
	config := &types.AmassConfig{
		Scope: &types.ScopeConfig{
			Domains: []string{input.Domain},
		},
		Options: &types.OptionsConfig{
			Active:      !input.Passive,
			BruteForce:  input.BruteForce,
			Alterations: input.Alterations,
		},
	}

	if input.TimeoutMinutes > 0 {
		config.Timeout = input.TimeoutMinutes * 60
	}

	// Create session
	sessionToken, err := h.graphqlClient.CreateSession(ctx, config)
	if err != nil {
		return "", err
	}

	// Start monitoring progress in background
	go h.monitorProgress(context.Background(), sessionToken, input.Domain)

	return sessionToken, nil
}

// getAmassPath returns the path to the amass binary
func getAmassPath() string {
	amassPath := os.Getenv("AMASS_PATH")
	if amassPath == "" {
		// Try common locations
		possiblePaths := []string{
			"/Users/rxerium/go/bin/amass",
			"/usr/local/bin/amass",
			"/opt/homebrew/bin/amass",
		}
		for _, path := range possiblePaths {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
		return "amass" // fallback to PATH
	}
	return amassPath
}

// getAmassDBDir returns the consistent database directory for amass operations
func getAmassDBDir() string {
	dbDir := filepath.Join(os.TempDir(), "amass-mcp-db")
	os.MkdirAll(dbDir, 0755)
	return dbDir
}

// EnumerateDomainDirect runs enumeration via docker-compose
func (h *Handler) EnumerateDomainDirect(ctx context.Context, domain string, passive bool) (string, error) {
	log.Printf("[Tools] Starting enumeration for %s via docker-compose\n", domain)

	composeDir := "/Users/rxerium/Documents/amass-docker-compose"

	// Build the enum command - service is named "enum" and domain is passed as argument
	args := []string{"-f", filepath.Join(composeDir, "compose.yaml"), "run", "--rm", "enum", "-d", domain}
	if passive {
		args = append(args, "-passive")
	}
	args = append(args, "-timeout", "5")

	// Run enumeration in background to avoid MCP timeout
	cmd := exec.Command("docker-compose", args...)
	cmd.Dir = composeDir

	log.Printf("[Docker] Running in background: docker-compose %v\n", args)

	// Start the command without waiting
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start enumeration: %w", err)
	}

	pid := cmd.Process.Pid
	log.Printf("[Docker] Enumeration started with PID: %d\n", pid)

	// Wait for container to start and get its name
	time.Sleep(2 * time.Second)
	containerCmd := exec.Command("docker", "ps", "--filter", "name=enum", "--filter", "label=com.docker.compose.service=enum", "--format", "{{.Names}}", "--latest")
	containerOutput, _ := containerCmd.CombinedOutput()
	containerName := strings.TrimSpace(string(containerOutput))

	// Track scan status with container name
	h.activeScans[domain] = &EnumStatus{
		Domain:        domain,
		StartTime:     time.Now(),
		PID:           pid,
		Passive:       passive,
		Running:       true,
		ContainerName: containerName,
	}

	log.Printf("[Docker] Tracking container: %s for domain: %s\n", containerName, domain)

	// Monitor completion in background by checking if specific container is still running
	go func(containerName string, domain string) {
		// Poll for container status every 10 seconds
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			<-ticker.C

			// Check if THIS specific container is still running
			checkCmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Names}}")
			output, err := checkCmd.CombinedOutput()
			outputStr := strings.TrimSpace(string(output))

			if err != nil || outputStr == "" || outputStr != containerName {
				// Container stopped, scan is done
				if status, ok := h.activeScans[domain]; ok {
					status.Running = false
					log.Printf("[Docker] Container %s stopped. Enumeration completed for %s\n", containerName, domain)
				}
				return
			}

			log.Printf("[Docker] Container %s still running for %s\n", containerName, domain)
		}
	}(containerName, domain)

	// Return immediately with status message
	return fmt.Sprintf("✓ Enumeration started for %s!\n\n🔍 Running %s scan in background (PID: %d)...\n\nThis will take approximately 5 minutes.\n\nCheck status with: amass_scan_status\nView results with: amass_list_subdomains", domain, map[bool]string{true: "passive", false: "active"}[passive], pid), nil
}

// monitorProgress monitors enumeration progress
func (h *Handler) monitorProgress(ctx context.Context, sessionToken, domain string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats, err := h.graphqlClient.GetSessionStats(ctx, sessionToken)
			if err != nil {
				log.Printf("[Progress] Error checking progress: %v\n", err)
				return
			}

			if stats.WorkItemsTotal > 0 {
				progress := float64(stats.WorkItemsCompleted) / float64(stats.WorkItemsTotal) * 100
				log.Printf("[Progress] %s: %d/%d (%.2f%%)\n",
					domain, stats.WorkItemsCompleted, stats.WorkItemsTotal, progress)

				if stats.WorkItemsCompleted >= stats.WorkItemsTotal {
					log.Printf("[Progress] Enumeration complete for %s\n", domain)
					return
				}
			}
		}
	}
}

// ListSubdomains lists discovered subdomains
func (h *Handler) ListSubdomains(ctx context.Context, input types.ListSubdomainsInput) ([]types.SubdomainResult, error) {
	log.Printf("[Tools] Listing subdomains for %s via PostgreSQL\n", input.Domain)

	// Query PostgreSQL directly using docker exec
	// The assetdb stores data in JSONB format in the entities table
	query := fmt.Sprintf("SELECT DISTINCT content->>'name' as name FROM entities WHERE etype='FQDN' AND content->>'name' LIKE '%%%s' ORDER BY name;", input.Domain)

	args := []string{"exec", "-i", "assetdb", "psql", "-U", "postgres", "-d", "assetdb", "-t", "-c", query}

	cmd := exec.CommandContext(ctx, "docker", args...)

	log.Printf("[Docker] Running: docker %v\n", args)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to query database: %w\nOutput: %s", err, string(output))
	}

	// Parse the output - each line is a subdomain
	lines := strings.Split(string(output), "\n")
	results := []types.SubdomainResult{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines
		if line == "" {
			continue
		}
		results = append(results, types.SubdomainResult{FQDN: line})
	}

	log.Printf("[Tools] Found %d subdomains for %s\n", len(results), input.Domain)
	return results, nil
}

// TrackChanges tracks changes in discovered assets
func (h *Handler) TrackChanges(ctx context.Context, input types.TrackChangesInput) ([]types.ChangeResult, error) {
	log.Printf("[Tools] Tracking changes for %s\n", input.Domain)
	return h.cliWrapper.TrackChanges(ctx, input)
}

// QueryAssociations queries asset associations
func (h *Handler) QueryAssociations(ctx context.Context, input types.QueryAssociationsInput) ([]types.AssociationResult, error) {
	log.Printf("[Tools] Querying associations for %s\n", input.Domain)

	// Use GetRelationships internally since it queries the database directly
	relationships, err := h.GetRelationships(ctx, input.Domain)
	if err != nil {
		return nil, err
	}

	// Convert to AssociationResult format
	results := []types.AssociationResult{}
	for _, rel := range relationships {
		fromAsset, _ := rel["from_asset"].(string)
		edgeType, _ := rel["edge_type"].(string)
		toAsset, _ := rel["to_asset"].(string)

		results = append(results, types.AssociationResult{
			Subject:   fromAsset,
			Predicate: edgeType,
			Object:    toAsset,
		})
	}

	return results, nil
}

// GenerateVisualization generates a network visualization
func (h *Handler) GenerateVisualization(ctx context.Context, input types.GenerateVisualizationInput) (map[string]string, error) {
	log.Printf("[Tools] Generating %s visualization for %s\n", input.Format, input.Domain)

	// Determine output path
	outputPath := input.OutputPath
	if outputPath == "" {
		ext := h.getFileExtension(input.Format)
		outputPath = filepath.Join(os.TempDir(), fmt.Sprintf("amass-viz-%s-%d.%s",
			input.Domain, time.Now().Unix(), ext))
	}

	input.OutputPath = outputPath
	content, err := h.cliWrapper.GenerateVisualization(ctx, input)
	if err != nil {
		return nil, err
	}

	// Try to read the generated file
	fileContent := content
	if data, err := os.ReadFile(outputPath); err == nil {
		fileContent = string(data)
	}

	return map[string]string{
		"content":   fileContent,
		"file_path": outputPath,
	}, nil
}

// GetConfig gets Amass configuration
func (h *Handler) GetConfig(input types.GetConfigInput) (any, error) {
	log.Println("[Tools] Getting configuration")

	if input.Section != "" {
		section, err := h.configManager.GetConfigSection(input.Section)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"section": input.Section,
			"value":   section,
		}, nil
	}

	return h.configManager.GetConfig()
}

// UpdateConfig updates Amass configuration
func (h *Handler) UpdateConfig(input types.UpdateConfigInput) (map[string]any, error) {
	log.Println("[Tools] Updating configuration")

	updatedConfig, err := h.configManager.UpdateConfig(input.Updates)
	if err != nil {
		return nil, err
	}

	result := map[string]any{
		"success": true,
		"config":  updatedConfig,
	}

	if input.Validate {
		valid, errors := h.configManager.ValidateConfig(updatedConfig)
		result["validation"] = map[string]any{
			"valid":  valid,
			"errors": errors,
		}
	}

	return result, nil
}

// AddAPIKey adds or updates an API key
func (h *Handler) AddAPIKey(input types.AddAPIKeyInput) (map[string]any, error) {
	log.Printf("[Tools] Adding API key for %s\n", input.Source)

	if err := h.configManager.AddAPIKey(input.Source, input.APIKey, input.AdditionalConfig); err != nil {
		return nil, err
	}

	return map[string]any{
		"success": true,
		"source":  input.Source,
		"message": fmt.Sprintf("API key successfully added/updated for %s", input.Source),
	}, nil
}

// GetEngineStatus gets the engine status
func (h *Handler) GetEngineStatus(ctx context.Context) (types.EngineStatus, error) {
	log.Println("[Tools] Getting engine status")
	return h.engineManager.GetEngineStatus(ctx), nil
}

// GetScanStatus gets the status of running/completed scans
func (h *Handler) GetScanStatus(ctx context.Context, domain string) (string, error) {
	log.Printf("[Tools] Getting scan status for %s\n", domain)

	if domain != "" {
		// Check specific domain
		if status, ok := h.activeScans[domain]; ok {
			elapsed := time.Since(status.StartTime)
			elapsedMins := int(elapsed.Minutes())

			if status.Running {
				return fmt.Sprintf("🔄 Scan in progress for %s\n\nMode: %s\nPID: %d\nElapsed: %d minutes / ~5 minutes\n\nThe scan is still running. Check back in a few minutes or use amass_list_subdomains to see partial results.",
					domain,
					map[bool]string{true: "passive", false: "active"}[status.Passive],
					status.PID,
					elapsedMins), nil
			} else {
				return fmt.Sprintf("✓ Scan completed for %s\n\nMode: %s\nDuration: %d minutes\n\nUse amass_list_subdomains to view results.",
					domain,
					map[bool]string{true: "passive", false: "active"}[status.Passive],
					elapsedMins), nil
			}
		}
		return fmt.Sprintf("No scan found for %s\n\nStart a scan with amass_enumerate_domain", domain), nil
	}

	// List all scans
	if len(h.activeScans) == 0 {
		return "No scans running or completed.\n\nStart a scan with amass_enumerate_domain", nil
	}

	var result strings.Builder
	result.WriteString("Active and Recent Scans:\n\n")
	for domain, status := range h.activeScans {
		elapsed := int(time.Since(status.StartTime).Minutes())
		statusIcon := "✓"
		statusText := "completed"
		if status.Running {
			statusIcon = "🔄"
			statusText = "running"
		}
		result.WriteString(fmt.Sprintf("%s %s - %s (%d mins, PID: %d)\n",
			statusIcon, domain, statusText, elapsed, status.PID))
	}

	return result.String(), nil
}

// GetProgress gets the progress of an enumeration session
func (h *Handler) GetProgress(ctx context.Context, sessionToken string) (string, error) {
	log.Printf("[Tools] Getting progress for session %s\n", sessionToken)

	stats, err := h.graphqlClient.GetSessionStats(ctx, sessionToken)
	if err != nil {
		return "", fmt.Errorf("failed to get session stats: %w", err)
	}

	if stats.WorkItemsTotal == 0 {
		return "Enumeration is starting up...\n\nNo work items yet. Check again in a few moments.", nil
	}

	percentage := float64(stats.WorkItemsCompleted) / float64(stats.WorkItemsTotal) * 100

	// Create a progress bar
	barLength := 40
	filled := int(percentage / 100 * float64(barLength))
	bar := ""
	for i := 0; i < barLength; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}

	status := "In Progress"
	if stats.WorkItemsCompleted >= stats.WorkItemsTotal {
		status = "Complete"
	}

	return fmt.Sprintf("Enumeration Progress:\n\n%s\n\nStatus: %s\nCompleted: %d / %d work items (%.1f%%)\n\nSession Token: %s",
		bar, status, stats.WorkItemsCompleted, stats.WorkItemsTotal, percentage, sessionToken), nil
}

// ListDataSources lists all configured data sources
func (h *Handler) ListDataSources() ([]string, error) {
	log.Println("[Tools] Listing data sources")
	return h.configManager.ListDataSources()
}

// FormatJSON formats a value as JSON string
func (h *Handler) FormatJSON(v any) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// getFileExtension returns file extension based on format
func (h *Handler) getFileExtension(format string) string {
	switch format {
	case "d3":
		return "html"
	case "dot":
		return "dot"
	case "gexf":
		return "gexf"
	default:
		return "txt"
	}
}

// GetIPAddresses gets all IP addresses for a domain
func (h *Handler) GetIPAddresses(ctx context.Context, domain string) ([]map[string]interface{}, error) {
	log.Printf("[Tools] Getting IP addresses for %s\n", domain)

	query := fmt.Sprintf(`SELECT DISTINCT content FROM entities WHERE etype='IPAddress' AND entity_id IN (SELECT to_entity_id FROM edges WHERE from_entity_id IN (SELECT entity_id FROM entities WHERE etype='FQDN' AND content->>'name' LIKE '%%%s%%'));`, domain)

	args := []string{"exec", "-i", "assetdb", "psql", "-U", "postgres", "-d", "assetdb", "-t", "-c", query}
	cmd := exec.CommandContext(ctx, "docker", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to query IPs: %w\nOutput: %s", err, string(output))
	}

	lines := strings.Split(string(output), "\n")
	results := []map[string]interface{}{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var data map[string]interface{}
		if err := json.Unmarshal([]byte(line), &data); err == nil {
			results = append(results, data)
		} else {
			log.Printf("[Tools] Failed to parse JSON: %s, error: %v\n", line, err)
		}
	}

	log.Printf("[Tools] Found %d IP addresses\n", len(results))
	return results, nil
}

// GetWhoisData gets WHOIS and contact records for a domain
func (h *Handler) GetWhoisData(ctx context.Context, domain string) ([]map[string]interface{}, error) {
	log.Printf("[Tools] Getting WHOIS data for %s\n", domain)

	query := fmt.Sprintf("SELECT content FROM entities WHERE etype='ContactRecord' AND content::text LIKE '%%%s%%';", domain)
	args := []string{"exec", "-i", "assetdb", "psql", "-U", "postgres", "-d", "assetdb", "-t", "-c", query}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to query WHOIS: %w\nOutput: %s", err, string(output))
	}

	lines := strings.Split(string(output), "\n")
	results := []map[string]interface{}{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var data map[string]interface{}
		if err := json.Unmarshal([]byte(line), &data); err == nil {
			results = append(results, data)
		}
	}

	log.Printf("[Tools] Found %d WHOIS records\n", len(results))
	return results, nil
}

// GetDomainInfo gets domain record information
func (h *Handler) GetDomainInfo(ctx context.Context, domain string) (map[string]interface{}, error) {
	log.Printf("[Tools] Getting domain info for %s\n", domain)

	query := fmt.Sprintf("SELECT content FROM entities WHERE etype='DomainRecord' AND content::text LIKE '%%%s%%' LIMIT 1;", domain)
	args := []string{"exec", "-i", "assetdb", "psql", "-U", "postgres", "-d", "assetdb", "-t", "-c", query}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to query domain info: %w\nOutput: %s", err, string(output))
	}

	line := strings.TrimSpace(string(output))
	if line == "" || !strings.HasPrefix(line, "{") {
		log.Printf("[Tools] No domain record found for %s\n", domain)
		return map[string]interface{}{
			"message": fmt.Sprintf("No domain record found for %s. Run an enumeration first.", domain),
		}, nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(line), &data); err != nil {
		return nil, fmt.Errorf("failed to parse domain record: %w", err)
	}

	log.Printf("[Tools] Found domain record for %s\n", domain)
	return data, nil
}

// GetAllAssets gets all asset types for a domain
func (h *Handler) GetAllAssets(ctx context.Context, domain string) (map[string][]map[string]interface{}, error) {
	log.Printf("[Tools] Getting all assets for %s\n", domain)

	query := fmt.Sprintf("SELECT etype, content FROM entities WHERE content::text LIKE '%%%s%%' ORDER BY etype;", domain)
	args := []string{"exec", "-i", "assetdb", "psql", "-U", "postgres", "-d", "assetdb", "-t", "-c", query}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to query assets: %w\nOutput: %s", err, string(output))
	}

	lines := strings.Split(string(output), "\n")
	results := make(map[string][]map[string]interface{})

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			log.Printf("[Tools] Skipping line (no pipe separator): %s\n", line)
			continue
		}

		etype := strings.TrimSpace(parts[0])
		content := strings.TrimSpace(parts[1])

		if !strings.HasPrefix(content, "{") {
			preview := content
			if len(preview) > 50 {
				preview = content[:50]
			}
			log.Printf("[Tools] Skipping line (no JSON): %s\n", preview)
			continue
		}

		var data map[string]interface{}
		if err := json.Unmarshal([]byte(content), &data); err == nil {
			results[etype] = append(results[etype], data)
		} else {
			log.Printf("[Tools] Failed to parse JSON for etype %s: %v\n", etype, err)
		}
	}

	totalAssets := 0
	for _, assets := range results {
		totalAssets += len(assets)
	}

	log.Printf("[Tools] Found %d assets across %d types\n", totalAssets, len(results))
	return results, nil
}

// GetRelationships gets relationships between assets
func (h *Handler) GetRelationships(ctx context.Context, domain string) ([]map[string]interface{}, error) {
	log.Printf("[Tools] Getting relationships for %s\n", domain)

	query := fmt.Sprintf(`
		SELECT
			e1.content->>'name' as from_asset,
			e1.etype as from_type,
			edges.etype as edge_type,
			e2.content->>'name' as to_asset,
			e2.etype as to_type
		FROM edges
		JOIN entities e1 ON edges.from_entity_id = e1.entity_id
		JOIN entities e2 ON edges.to_entity_id = e2.entity_id
		WHERE e1.entity_id IN (
			SELECT entity_id FROM entities
			WHERE content::text LIKE '%%%s%%'
		)
		LIMIT 100;
	`, domain)

	args := []string{"exec", "-i", "assetdb", "psql", "-U", "postgres", "-d", "assetdb", "-t", "-c", query}
	cmd := exec.CommandContext(ctx, "docker", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to query relationships: %w\nOutput: %s", err, string(output))
	}

	lines := strings.Split(string(output), "\n")
	results := []map[string]interface{}{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) >= 5 {
			result := map[string]interface{}{
				"from_asset": strings.TrimSpace(parts[0]),
				"from_type":  strings.TrimSpace(parts[1]),
				"edge_type":  strings.TrimSpace(parts[2]),
				"to_asset":   strings.TrimSpace(parts[3]),
				"to_type":    strings.TrimSpace(parts[4]),
			}
			results = append(results, result)
		}
	}

	log.Printf("[Tools] Found %d relationships\n", len(results))
	return results, nil
}
