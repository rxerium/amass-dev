// Package types defines all data structures used by the MCP server
package types

import "time"

// SubdomainResult represents a discovered subdomain
type SubdomainResult struct {
	FQDN string   `json:"fqdn"`
	IPv4 []string `json:"ipv4,omitempty"`
	IPv6 []string `json:"ipv6,omitempty"`
}

// ChangeResult represents a change in discovered assets
type ChangeResult struct {
	Timestamp  time.Time `json:"timestamp"`
	Asset      string    `json:"asset"`
	AssetType  string    `json:"asset_type"`
	ChangeType string    `json:"change_type"` // new, modified, deleted
}

// AssociationResult represents an asset association from graph traversal
type AssociationResult struct {
	Subject   string `json:"subject"`
	Predicate string `json:"predicate"`
	Object    string `json:"object"`
}

// AmassConfig represents the Amass configuration structure
type AmassConfig struct {
	Scope       *ScopeConfig       `yaml:"scope,omitempty" json:"scope,omitempty"`
	Options     *OptionsConfig     `yaml:"options,omitempty" json:"options,omitempty"`
	DataSources map[string]any     `yaml:"datasources,omitempty" json:"datasources,omitempty"`
	BruteForce  *BruteForceConfig  `yaml:"bruteforce,omitempty" json:"bruteforce,omitempty"`
	Alterations *AlterationsConfig `yaml:"alterations,omitempty" json:"alterations,omitempty"`
	MaxDNS      int                `yaml:"max_dns_queries,omitempty" json:"max_dns_queries,omitempty"`
	Timeout     int                `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// ScopeConfig defines the enumeration scope
type ScopeConfig struct {
	Domains []string `yaml:"domains,omitempty" json:"domains,omitempty"`
	IPs     []string `yaml:"ips,omitempty" json:"ips,omitempty"`
	CIDRs   []string `yaml:"cidrs,omitempty" json:"cidrs,omitempty"`
	ASNs    []int    `yaml:"asns,omitempty" json:"asns,omitempty"`
	Ports   []int    `yaml:"ports,omitempty" json:"ports,omitempty"`
}

// OptionsConfig defines enumeration options
type OptionsConfig struct {
	Active             bool `yaml:"active,omitempty" json:"active,omitempty"`
	BruteForce         bool `yaml:"brute_force,omitempty" json:"brute_force,omitempty"`
	Alterations        bool `yaml:"alterations,omitempty" json:"alterations,omitempty"`
	Recursive          bool `yaml:"recursive,omitempty" json:"recursive,omitempty"`
	MinForRecursive    int  `yaml:"minimum_for_recursive,omitempty" json:"minimum_for_recursive,omitempty"`
}

// BruteForceConfig defines brute force settings
type BruteForceConfig struct {
	Enabled            bool     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Wordlists          []string `yaml:"wordlists,omitempty" json:"wordlists,omitempty"`
	Recursive          bool     `yaml:"recursive,omitempty" json:"recursive,omitempty"`
	MinForRecursive    int      `yaml:"minimum_for_recursive,omitempty" json:"minimum_for_recursive,omitempty"`
}

// AlterationsConfig defines alteration settings
type AlterationsConfig struct {
	Enabled      bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	EditDistance int  `yaml:"edit_distance,omitempty" json:"edit_distance,omitempty"`
	FlipWords    bool `yaml:"flip_words,omitempty" json:"flip_words,omitempty"`
	FlipNumbers  bool `yaml:"flip_numbers,omitempty" json:"flip_numbers,omitempty"`
	AddWords     bool `yaml:"add_words,omitempty" json:"add_words,omitempty"`
	AddNumbers   bool `yaml:"add_numbers,omitempty" json:"add_numbers,omitempty"`
}

// SessionStats represents GraphQL session statistics
type SessionStats struct {
	WorkItemsCompleted int `json:"WorkItemsCompleted"`
	WorkItemsTotal     int `json:"WorkItemsTotal"`
}

// EngineStatus represents the status of the Amass engine
type EngineStatus struct {
	Running bool   `json:"running"`
	Healthy bool   `json:"healthy"`
	URL     string `json:"url"`
	Port    int    `json:"port"`
	Uptime  int64  `json:"uptime,omitempty"`
	Message string `json:"message"`
}

// Tool input types for MCP

// EnumerateDomainInput contains parameters for domain enumeration
type EnumerateDomainInput struct {
	Domain         string   `json:"domain"`
	Passive        bool     `json:"passive,omitempty"`
	BruteForce     bool     `json:"brute_force,omitempty"`
	Alterations    bool     `json:"alterations,omitempty"`
	TimeoutMinutes int      `json:"timeout_minutes,omitempty"`
	SourcesInclude []string `json:"sources_include,omitempty"`
	SourcesExclude []string `json:"sources_exclude,omitempty"`
}

// ListSubdomainsInput contains parameters for listing subdomains
type ListSubdomainsInput struct {
	Domain        string `json:"domain"`
	SessionToken  string `json:"session_token,omitempty"`
	ShowIPs       bool   `json:"show_ips,omitempty"`
	ShowIPv4Only  bool   `json:"show_ipv4_only,omitempty"`
	ShowIPv6Only  bool   `json:"show_ipv6_only,omitempty"`
}

// TrackChangesInput contains parameters for tracking changes
type TrackChangesInput struct {
	Domain string `json:"domain"`
	Since  string `json:"since"`
}

// QueryAssociationsInput contains parameters for querying associations
type QueryAssociationsInput struct {
	Domain      string `json:"domain"`
	WalkPattern string `json:"walk_pattern,omitempty"`
}

// GenerateVisualizationInput contains parameters for generating visualizations
type GenerateVisualizationInput struct {
	Domain     string `json:"domain"`
	Format     string `json:"format"` // d3, dot, gexf
	OutputPath string `json:"output_path,omitempty"`
}

// GetConfigInput contains parameters for getting configuration
type GetConfigInput struct {
	Section string `json:"section,omitempty"`
}

// UpdateConfigInput contains parameters for updating configuration
type UpdateConfigInput struct {
	Updates  map[string]any `json:"updates"`
	Validate bool           `json:"validate,omitempty"`
}

// AddAPIKeyInput contains parameters for adding API keys
type AddAPIKeyInput struct {
	Source           string         `json:"source"`
	APIKey           string         `json:"api_key"`
	AdditionalConfig map[string]any `json:"additional_config,omitempty"`
}
