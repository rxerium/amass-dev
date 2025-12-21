// Package config manages Amass configuration files
package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/owasp-amass/amass/mcp-server/internal/types"
)

// Manager manages Amass configuration
type Manager struct {
	configDir  string
	configPath string
}

// NewManager creates a new config manager
func NewManager(configDir string) *Manager {
	if configDir == "" {
		home, _ := os.UserHomeDir()
		configDir = filepath.Join(home, ".config", "amass")
	}

	return &Manager{
		configDir:  configDir,
		configPath: filepath.Join(configDir, "config.yaml"),
	}
}

// ConfigExists checks if the config file exists
func (m *Manager) ConfigExists() bool {
	_, err := os.Stat(m.configPath)
	return err == nil
}

// ensureConfigDir ensures the config directory exists
func (m *Manager) ensureConfigDir() error {
	return os.MkdirAll(m.configDir, 0755)
}

// GetConfig reads the Amass configuration file
func (m *Manager) GetConfig() (*types.AmassConfig, error) {
	if !m.ConfigExists() {
		log.Println("[ConfigManager] Config file does not exist, returning empty config")
		return &types.AmassConfig{}, nil
	}

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config types.AmassConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &config, nil
}

// GetConfigSection gets a specific section of the config
func (m *Manager) GetConfigSection(section string) (any, error) {
	config, err := m.GetConfig()
	if err != nil {
		return nil, err
	}

	switch section {
	case "scope":
		return config.Scope, nil
	case "options":
		return config.Options, nil
	case "datasources":
		return config.DataSources, nil
	case "bruteforce":
		return config.BruteForce, nil
	case "alterations":
		return config.Alterations, nil
	default:
		return nil, fmt.Errorf("unknown config section: %s", section)
	}
}

// WriteConfig writes the entire configuration file
func (m *Manager) WriteConfig(config *types.AmassConfig) error {
	if err := m.ensureConfigDir(); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(m.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	log.Println("[ConfigManager] Config file written successfully")
	return nil
}

// UpdateConfig updates configuration with new values (merge)
func (m *Manager) UpdateConfig(updates map[string]any) (*types.AmassConfig, error) {
	config, err := m.GetConfig()
	if err != nil {
		return nil, err
	}

	// Merge updates into config
	merged := m.deepMerge(config, updates)

	if err := m.WriteConfig(merged); err != nil {
		return nil, err
	}

	return merged, nil
}

// AddAPIKey adds or updates an API key for a data source
func (m *Manager) AddAPIKey(sourceName, apiKey string, additionalConfig map[string]any) error {
	config, err := m.GetConfig()
	if err != nil {
		return err
	}

	// Initialize datasources if nil
	if config.DataSources == nil {
		config.DataSources = make(map[string]any)
	}

	// Create data source entry
	sourceConfig := map[string]any{
		"name":   sourceName,
		"apikey": apiKey,
	}

	// Merge additional config
	for k, v := range additionalConfig {
		sourceConfig[k] = v
	}

	config.DataSources[sourceName] = sourceConfig

	if err := m.WriteConfig(config); err != nil {
		return err
	}

	log.Printf("[ConfigManager] API key added for %s\n", sourceName)
	return nil
}

// ListDataSources lists all configured data sources
func (m *Manager) ListDataSources() ([]string, error) {
	config, err := m.GetConfig()
	if err != nil {
		return nil, err
	}

	if config.DataSources == nil {
		return []string{}, nil
	}

	sources := make([]string, 0, len(config.DataSources))
	for name := range config.DataSources {
		sources = append(sources, name)
	}

	return sources, nil
}

// ValidateConfig validates the configuration (basic validation)
func (m *Manager) ValidateConfig(config *types.AmassConfig) (bool, []string) {
	errors := []string{}

	// Validate scope
	if config.Scope != nil {
		// Basic validation - could be extended
		if config.Scope.Domains != nil && len(config.Scope.Domains) == 0 {
			errors = append(errors, "scope.domains cannot be empty array")
		}
	}

	return len(errors) == 0, errors
}

// GetConfigPath returns the config file path
func (m *Manager) GetConfigPath() string {
	return m.configPath
}

// GetConfigDir returns the config directory path
func (m *Manager) GetConfigDir() string {
	return m.configDir
}

// deepMerge deep merges source into target
func (m *Manager) deepMerge(target *types.AmassConfig, source map[string]any) *types.AmassConfig {
	// This is a simplified merge - in production, you'd want a more robust solution
	// For now, we'll just convert to YAML and back
	data, _ := yaml.Marshal(target)
	var targetMap map[string]any
	yaml.Unmarshal(data, &targetMap)

	// Merge source into targetMap
	for k, v := range source {
		targetMap[k] = v
	}

	// Convert back to AmassConfig
	data, _ = yaml.Marshal(targetMap)
	var result types.AmassConfig
	yaml.Unmarshal(data, &result)

	return &result
}
