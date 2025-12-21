// Package cli wraps Amass CLI commands
package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/owasp-amass/amass/mcp-server/internal/types"
)

// Wrapper wraps Amass CLI commands
type Wrapper struct {
	amassPath string
}

// NewWrapper creates a new CLI wrapper
func NewWrapper(amassPath string) *Wrapper {
	if amassPath == "" {
		amassPath = "amass"
	}
	return &Wrapper{amassPath: amassPath}
}

// executeCommand executes an Amass command and returns the output
func (w *Wrapper) executeCommand(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, w.amassPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Printf("[CLI] Executing: %s %v\n", w.amassPath, args)

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("command failed: %w, stderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// ListSubdomains lists subdomains for a domain
func (w *Wrapper) ListSubdomains(ctx context.Context, input types.ListSubdomainsInput) ([]types.SubdomainResult, error) {
	log.Printf("[CLI] Listing subdomains for %s\n", input.Domain)

	args := []string{"subs", "-d", input.Domain}

	if input.ShowIPs {
		args = append(args, "-ip")
	} else if input.ShowIPv4Only {
		args = append(args, "-ipv4")
	} else if input.ShowIPv6Only {
		args = append(args, "-ipv6")
	}

	output, err := w.executeCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	return w.parseSubdomainsOutput(output, input.ShowIPs || input.ShowIPv4Only || input.ShowIPv6Only), nil
}

// TrackChanges tracks changes in discovered assets
func (w *Wrapper) TrackChanges(ctx context.Context, input types.TrackChangesInput) ([]types.ChangeResult, error) {
	log.Printf("[CLI] Tracking changes for %s since %s\n", input.Domain, input.Since)

	args := []string{"track", "-d", input.Domain, "-since", input.Since}

	output, err := w.executeCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	return w.parseTrackOutput(output), nil
}

// GenerateVisualization generates a visualization
func (w *Wrapper) GenerateVisualization(ctx context.Context, input types.GenerateVisualizationInput) (string, error) {
	log.Printf("[CLI] Generating %s visualization for %s\n", input.Format, input.Domain)

	args := []string{"viz"}

	// Add format flag
	switch input.Format {
	case "d3":
		args = append(args, "-d3")
	case "dot":
		args = append(args, "-dot")
	case "gexf":
		args = append(args, "-gexf")
	default:
		return "", fmt.Errorf("unsupported format: %s", input.Format)
	}

	args = append(args, "-d", input.Domain)

	// Add output path if specified
	if input.OutputPath != "" {
		args = append(args, "-o", input.OutputPath)
	}

	output, err := w.executeCommand(ctx, args...)
	if err != nil {
		return "", err
	}

	return output, nil
}

// QueryAssociations queries asset associations
func (w *Wrapper) QueryAssociations(ctx context.Context, input types.QueryAssociationsInput) ([]types.AssociationResult, error) {
	log.Printf("[CLI] Querying associations for %s\n", input.Domain)

	args := []string{"assoc", "-d", input.Domain}

	if input.WalkPattern != "" {
		args = append(args, "-t1", input.WalkPattern)
	}

	output, err := w.executeCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	return w.parseAssociationsOutput(output), nil
}

// GetVersion gets the Amass version
func (w *Wrapper) GetVersion(ctx context.Context) (string, error) {
	output, err := w.executeCommand(ctx, "--version")
	if err != nil {
		return "unknown", nil
	}

	return strings.TrimSpace(output), nil
}

// parseSubdomainsOutput parses subdomain output
func (w *Wrapper) parseSubdomainsOutput(output string, includeIPs bool) []types.SubdomainResult {
	results := []types.SubdomainResult{}
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if includeIPs {
			// Format: "subdomain.example.com,1.2.3.4"
			parts := strings.Split(line, ",")
			if len(parts) < 1 {
				continue
			}

			fqdn := strings.TrimSpace(parts[0])
			result := types.SubdomainResult{FQDN: fqdn}

			if len(parts) > 1 {
				ipv4 := []string{}
				ipv6 := []string{}

				for _, ip := range parts[1:] {
					ip = strings.TrimSpace(ip)
					if strings.Contains(ip, ":") {
						ipv6 = append(ipv6, ip)
					} else if strings.Contains(ip, ".") {
						ipv4 = append(ipv4, ip)
					}
				}

				if len(ipv4) > 0 {
					result.IPv4 = ipv4
				}
				if len(ipv6) > 0 {
					result.IPv6 = ipv6
				}
			}

			results = append(results, result)
		} else {
			// Just the subdomain name
			results = append(results, types.SubdomainResult{FQDN: line})
		}
	}

	return results
}

// parseTrackOutput parses track output
func (w *Wrapper) parseTrackOutput(output string) []types.ChangeResult {
	results := []types.ChangeResult{}
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Track output typically shows timestamp and discovered assets
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			results = append(results, types.ChangeResult{
				Asset:      strings.Join(parts[1:], " "),
				AssetType:  "unknown",
				ChangeType: "new",
			})
		}
	}

	return results
}

// parseAssociationsOutput parses association output (JSON format)
func (w *Wrapper) parseAssociationsOutput(output string) []types.AssociationResult {
	results := []types.AssociationResult{}

	// Try to parse as JSON array first
	var jsonArray []types.AssociationResult
	if err := json.Unmarshal([]byte(output), &jsonArray); err == nil {
		return jsonArray
	}

	// Otherwise, parse line by line as JSON objects
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var assoc types.AssociationResult
		if err := json.Unmarshal([]byte(line), &assoc); err == nil {
			results = append(results, assoc)
		}
	}

	return results
}
