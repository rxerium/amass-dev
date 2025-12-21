// Package engine manages the Amass engine lifecycle
package engine

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/owasp-amass/amass/mcp-server/internal/types"
)

// Manager manages the Amass engine process
type Manager struct {
	amassPath       string
	engineURL       string
	enginePort      int
	startupTimeout  time.Duration
	healthCheckInterval time.Duration
	cmd             *exec.Cmd
}

// NewManager creates a new engine manager
func NewManager(amassPath, engineURL string, startupTimeout, healthCheckInterval time.Duration) *Manager {
	return &Manager{
		amassPath:       amassPath,
		engineURL:       engineURL,
		enginePort:      4000,
		startupTimeout:  startupTimeout,
		healthCheckInterval: healthCheckInterval,
	}
}

// IsEngineRunning checks if the Amass engine is running and healthy
func (m *Manager) IsEngineRunning(ctx context.Context) bool {
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "POST", m.engineURL, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest
}

// GetEngineStatus returns detailed engine status
func (m *Manager) GetEngineStatus(ctx context.Context) types.EngineStatus {
	running := m.IsEngineRunning(ctx)

	message := "Engine is running"
	if !running {
		message = "Engine is not running"
	}

	return types.EngineStatus{
		Running: running,
		Healthy: running,
		URL:     m.engineURL,
		Port:    m.enginePort,
		Message: message,
	}
}

// StartEngine starts the Amass engine process
func (m *Manager) StartEngine(ctx context.Context) error {
	if m.IsEngineRunning(ctx) {
		log.Println("[EngineManager] Engine is already running")
		return nil
	}

	log.Println("[EngineManager] Starting Amass engine...")

	// Start the engine process
	m.cmd = exec.CommandContext(ctx, m.amassPath, "engine")

	// Capture output for logging
	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start engine: %w", err)
	}

	log.Printf("[EngineManager] Engine process started with PID: %d\n", m.cmd.Process.Pid)

	// Wait for engine to be ready
	deadline := time.Now().Add(m.startupTimeout)
	ticker := time.NewTicker(m.healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.StopEngine()
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				m.StopEngine()
				return fmt.Errorf("engine failed to start within timeout")
			}

			if m.IsEngineRunning(ctx) {
				log.Println("[EngineManager] Engine is ready and accepting connections")
				return nil
			}
		}
	}
}

// StopEngine stops the Amass engine process
func (m *Manager) StopEngine() {
	if m.cmd == nil || m.cmd.Process == nil {
		log.Println("[EngineManager] No engine process to stop")
		return
	}

	log.Println("[EngineManager] Stopping Amass engine...")

	// Try graceful shutdown
	if err := m.cmd.Process.Signal(os.Interrupt); err != nil {
		log.Printf("[EngineManager] Error sending interrupt: %v\n", err)
		// Force kill
		m.cmd.Process.Kill()
	}

	// Wait for process to exit
	go func() {
		m.cmd.Wait()
		log.Println("[EngineManager] Engine process stopped")
	}()

	m.cmd = nil
}

// EnsureEngine ensures the engine is running, starting it if necessary
func (m *Manager) EnsureEngine(ctx context.Context) error {
	if m.IsEngineRunning(ctx) {
		return nil
	}

	return m.StartEngine(ctx)
}

// Cleanup releases resources
func (m *Manager) Cleanup() {
	m.StopEngine()
}
