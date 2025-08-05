// Copyright (c) 2024 KrakenFS Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package volume

import (
	"encoding/json"
	"fmt"
	"os"

	"go.uber.org/zap"
)

// PluginRequest represents a Docker volume plugin request.
type PluginRequest struct {
	Name string            `json:"Name"`
	Opts map[string]string `json:"Opts,omitempty"`
}

// PluginResponse represents a Docker volume plugin response.
type PluginResponse struct {
	Err string `json:"Err,omitempty"`
}

// MountResponse represents a mount response.
type MountResponse struct {
	Mountpoint string `json:"Mountpoint"`
	Err        string `json:"Err,omitempty"`
}

// Plugin manages Docker volume plugin operations.
type Plugin struct {
	driver *Driver
	logger *zap.Logger
}

// NewPlugin creates a new Docker volume plugin.
func NewPlugin(driver *Driver, logger *zap.Logger) *Plugin {
	return &Plugin{
		driver: driver,
		logger: logger,
	}
}

// HandleRequest handles Docker volume plugin requests.
func (p *Plugin) HandleRequest() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("plugin operation not specified")
	}

	operation := os.Args[1]
	p.logger.Info("Handling plugin request", zap.String("operation", operation))

	switch operation {
	case "create":
		return p.handleCreate()
	case "remove":
		return p.handleRemove()
	case "mount":
		return p.handleMount()
	case "unmount":
		return p.handleUnmount()
	case "path":
		return p.handlePath()
	case "list":
		return p.handleList()
	case "get":
		return p.handleGet()
	case "capabilities":
		return p.handleCapabilities()
	default:
		return fmt.Errorf("unknown operation: %s", operation)
	}
}

// handleCreate handles volume creation.
func (p *Plugin) handleCreate() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("volume name not specified")
	}

	volumeName := os.Args[2]
	p.logger.Info("Creating volume", zap.String("name", volumeName))

	// Parse options from stdin
	var req PluginRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return fmt.Errorf("decode request: %s", err)
	}

	// Create volume
	if err := p.driver.Create(volumeName, req.Opts); err != nil {
		resp := PluginResponse{Err: err.Error()}
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	resp := PluginResponse{}
	return json.NewEncoder(os.Stdout).Encode(resp)
}

// handleRemove handles volume removal.
func (p *Plugin) handleRemove() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("volume name not specified")
	}

	volumeName := os.Args[2]
	p.logger.Info("Removing volume", zap.String("name", volumeName))

	if err := p.driver.Remove(volumeName); err != nil {
		resp := PluginResponse{Err: err.Error()}
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	resp := PluginResponse{}
	return json.NewEncoder(os.Stdout).Encode(resp)
}

// handleMount handles volume mounting.
func (p *Plugin) handleMount() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("volume name not specified")
	}

	volumeName := os.Args[2]
	mountID := os.Args[3] // Container ID
	p.logger.Info("Mounting volume", zap.String("name", volumeName), zap.String("id", mountID))

	mountPath, err := p.driver.Mount(volumeName, mountID)
	if err != nil {
		resp := MountResponse{Err: err.Error()}
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	resp := MountResponse{Mountpoint: mountPath}
	return json.NewEncoder(os.Stdout).Encode(resp)
}

// handleUnmount handles volume unmounting.
func (p *Plugin) handleUnmount() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("volume name not specified")
	}

	volumeName := os.Args[2]
	p.logger.Info("Unmounting volume", zap.String("name", volumeName))

	if err := p.driver.Unmount(volumeName); err != nil {
		resp := PluginResponse{Err: err.Error()}
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	resp := PluginResponse{}
	return json.NewEncoder(os.Stdout).Encode(resp)
}

// handlePath handles volume path requests.
func (p *Plugin) handlePath() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("volume name not specified")
	}

	volumeName := os.Args[2]
	volume, err := p.driver.Get(volumeName)
	if err != nil {
		resp := PluginResponse{Err: err.Error()}
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	resp := MountResponse{Mountpoint: volume.Path}
	return json.NewEncoder(os.Stdout).Encode(resp)
}

// handleList handles volume listing.
func (p *Plugin) handleList() error {
	volumes, err := p.driver.List()
	if err != nil {
		resp := PluginResponse{Err: err.Error()}
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	// Convert to Docker plugin format
	var volumeList []map[string]interface{}
	for _, volume := range volumes {
		volumeList = append(volumeList, map[string]interface{}{
			"Name":       volume.Name,
			"Mountpoint": volume.Path,
			"Status":     map[string]interface{}{},
		})
	}

	return json.NewEncoder(os.Stdout).Encode(volumeList)
}

// handleGet handles volume information requests.
func (p *Plugin) handleGet() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("volume name not specified")
	}

	volumeName := os.Args[2]
	volume, err := p.driver.Get(volumeName)
	if err != nil {
		resp := PluginResponse{Err: err.Error()}
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	resp := map[string]interface{}{
		"volume": map[string]interface{}{
			"Name":       volume.Name,
			"Mountpoint": volume.Path,
			"Status":     map[string]interface{}{},
		},
	}

	return json.NewEncoder(os.Stdout).Encode(resp)
}

// handleCapabilities handles capability requests.
func (p *Plugin) handleCapabilities() error {
	capabilities := map[string]interface{}{
		"Scope": "global",
	}

	return json.NewEncoder(os.Stdout).Encode(capabilities)
}
