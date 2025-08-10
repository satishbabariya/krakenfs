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
	"net"
	"net/http"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// DockerPlugin implements the Docker Volume Plugin API v2.
type DockerPlugin struct {
	driver     *Driver
	logger     *zap.Logger
	socketPath string
	listener   net.Listener
	server     *http.Server
}

// VolumeCreateRequest represents a Docker volume create request.
type VolumeCreateRequest struct {
	Name    string            `json:"Name"`
	Options map[string]string `json:"Opts,omitempty"`
}

// VolumeCreateResponse represents a Docker volume create response.
type VolumeCreateResponse struct {
	Err string `json:"Err,omitempty"`
}

// VolumeRemoveRequest represents a Docker volume remove request.
type VolumeRemoveRequest struct {
	Name string `json:"Name"`
}

// VolumeRemoveResponse represents a Docker volume remove response.
type VolumeRemoveResponse struct {
	Err string `json:"Err,omitempty"`
}

// VolumeMountRequest represents a Docker volume mount request.
type VolumeMountRequest struct {
	Name string `json:"Name"`
	ID   string `json:"ID"`
}

// VolumeMountResponse represents a Docker volume mount response.
type VolumeMountResponse struct {
	Mountpoint string `json:"Mountpoint,omitempty"`
	Err        string `json:"Err,omitempty"`
}

// VolumeUnmountRequest represents a Docker volume unmount request.
type VolumeUnmountRequest struct {
	Name string `json:"Name"`
	ID   string `json:"ID"`
}

// VolumeUnmountResponse represents a Docker volume unmount response.
type VolumeUnmountResponse struct {
	Err string `json:"Err,omitempty"`
}

// VolumePathRequest represents a Docker volume path request.
type VolumePathRequest struct {
	Name string `json:"Name"`
}

// VolumePathResponse represents a Docker volume path response.
type VolumePathResponse struct {
	Mountpoint string `json:"Mountpoint,omitempty"`
	Err        string `json:"Err,omitempty"`
}

// VolumeListResponse represents a Docker volume list response.
type VolumeListResponse struct {
	Volumes []DockerVolume `json:"Volumes,omitempty"`
	Err     string         `json:"Err,omitempty"`
}

// VolumeGetRequest represents a Docker volume get request.
type VolumeGetRequest struct {
	Name string `json:"Name"`
}

// VolumeGetResponse represents a Docker volume get response.
type VolumeGetResponse struct {
	Volume *DockerVolume `json:"Volume,omitempty"`
	Err    string        `json:"Err,omitempty"`
}

// DockerVolume represents a Docker volume.
type DockerVolume struct {
	Name       string                 `json:"Name"`
	Mountpoint string                 `json:"Mountpoint"`
	Status     map[string]interface{} `json:"Status,omitempty"`
}

// CapabilitiesResponse represents the plugin capabilities response.
type CapabilitiesResponse struct {
	Capabilities Capabilities `json:"Capabilities"`
}

// Capabilities represents the plugin capabilities.
type Capabilities struct {
	Scope string `json:"Scope"`
}

// NewDockerPlugin creates a new Docker-compliant volume plugin.
func NewDockerPlugin(driver *Driver, logger *zap.Logger) *DockerPlugin {
	socketPath := "/run/docker/plugins/krakenfs.sock"
	
	return &DockerPlugin{
		driver:     driver,
		logger:     logger,
		socketPath: socketPath,
	}
}

// Start starts the Docker plugin HTTP server.
func (dp *DockerPlugin) Start() error {
	// Remove existing socket file
	if err := os.RemoveAll(dp.socketPath); err != nil {
		return fmt.Errorf("remove existing socket: %w", err)
	}

	// Create socket directory
	if err := os.MkdirAll(filepath.Dir(dp.socketPath), 0755); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", dp.socketPath)
	if err != nil {
		return fmt.Errorf("create socket listener: %w", err)
	}
	dp.listener = listener

	// Set up HTTP router
	mux := http.NewServeMux()
	
	// Plugin activation
	mux.HandleFunc("/Plugin.Activate", dp.handleActivate)
	
	// Volume driver endpoints
	mux.HandleFunc("/VolumeDriver.Create", dp.handleCreate)
	mux.HandleFunc("/VolumeDriver.Remove", dp.handleRemove)
	mux.HandleFunc("/VolumeDriver.Mount", dp.handleMount)
	mux.HandleFunc("/VolumeDriver.Path", dp.handlePath)
	mux.HandleFunc("/VolumeDriver.Unmount", dp.handleUnmount)
	mux.HandleFunc("/VolumeDriver.Get", dp.handleGet)
	mux.HandleFunc("/VolumeDriver.List", dp.handleList)
	mux.HandleFunc("/VolumeDriver.Capabilities", dp.handleCapabilities)

	// Create HTTP server
	dp.server = &http.Server{
		Handler: mux,
	}

	dp.logger.Info("Starting Docker plugin HTTP server",
		zap.String("socket_path", dp.socketPath))

	// Start serving
	go func() {
		if err := dp.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			dp.logger.Error("Plugin server error", zap.Error(err))
		}
	}()

	return nil
}

// Stop stops the Docker plugin HTTP server.
func (dp *DockerPlugin) Stop() error {
	if dp.server != nil {
		if err := dp.server.Close(); err != nil {
			return err
		}
	}

	if dp.listener != nil {
		dp.listener.Close()
	}

	// Remove socket file
	return os.RemoveAll(dp.socketPath)
}

// handleActivate handles plugin activation requests.
func (dp *DockerPlugin) handleActivate(w http.ResponseWriter, r *http.Request) {
	dp.logger.Debug("Plugin activation request")
	
	response := []string{"VolumeDriver"}
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		dp.logger.Error("Failed to encode activation response", zap.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleCreate handles volume creation requests.
func (dp *DockerPlugin) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req VolumeCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		dp.sendError(w, fmt.Sprintf("decode request: %s", err))
		return
	}

	dp.logger.Info("Creating volume", zap.String("name", req.Name))

	err := dp.driver.Create(req.Name, req.Options)
	if err != nil {
		dp.sendError(w, err.Error())
		return
	}

	resp := VolumeCreateResponse{}
	dp.sendResponse(w, resp)
}

// handleRemove handles volume removal requests.
func (dp *DockerPlugin) handleRemove(w http.ResponseWriter, r *http.Request) {
	var req VolumeRemoveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		dp.sendError(w, fmt.Sprintf("decode request: %s", err))
		return
	}

	dp.logger.Info("Removing volume", zap.String("name", req.Name))

	err := dp.driver.Remove(req.Name)
	if err != nil {
		dp.sendError(w, err.Error())
		return
	}

	resp := VolumeRemoveResponse{}
	dp.sendResponse(w, resp)
}

// handleMount handles volume mount requests.
func (dp *DockerPlugin) handleMount(w http.ResponseWriter, r *http.Request) {
	var req VolumeMountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		dp.sendError(w, fmt.Sprintf("decode request: %s", err))
		return
	}

	dp.logger.Info("Mounting volume", 
		zap.String("name", req.Name), 
		zap.String("id", req.ID))

	mountpoint, err := dp.driver.Mount(req.Name, req.ID)
	if err != nil {
		resp := VolumeMountResponse{Err: err.Error()}
		dp.sendResponse(w, resp)
		return
	}

	resp := VolumeMountResponse{Mountpoint: mountpoint}
	dp.sendResponse(w, resp)
}

// handleUnmount handles volume unmount requests.
func (dp *DockerPlugin) handleUnmount(w http.ResponseWriter, r *http.Request) {
	var req VolumeUnmountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		dp.sendError(w, fmt.Sprintf("decode request: %s", err))
		return
	}

	dp.logger.Info("Unmounting volume", 
		zap.String("name", req.Name), 
		zap.String("id", req.ID))

	err := dp.driver.Unmount(req.Name)
	if err != nil {
		resp := VolumeUnmountResponse{Err: err.Error()}
		dp.sendResponse(w, resp)
		return
	}

	resp := VolumeUnmountResponse{}
	dp.sendResponse(w, resp)
}

// handlePath handles volume path requests.
func (dp *DockerPlugin) handlePath(w http.ResponseWriter, r *http.Request) {
	var req VolumePathRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		dp.sendError(w, fmt.Sprintf("decode request: %s", err))
		return
	}

	volume, err := dp.driver.Get(req.Name)
	if err != nil {
		resp := VolumePathResponse{Err: err.Error()}
		dp.sendResponse(w, resp)
		return
	}

	resp := VolumePathResponse{Mountpoint: volume.Path}
	dp.sendResponse(w, resp)
}

// handleList handles volume list requests.
func (dp *DockerPlugin) handleList(w http.ResponseWriter, r *http.Request) {
	volumes, err := dp.driver.List()
	if err != nil {
		resp := VolumeListResponse{Err: err.Error()}
		dp.sendResponse(w, resp)
		return
	}

	dockerVolumes := make([]DockerVolume, len(volumes))
	for i, volume := range volumes {
		dockerVolumes[i] = DockerVolume{
			Name:       volume.Name,
			Mountpoint: volume.Path,
			Status:     map[string]interface{}{},
		}
	}

	resp := VolumeListResponse{Volumes: dockerVolumes}
	dp.sendResponse(w, resp)
}

// handleGet handles volume get requests.
func (dp *DockerPlugin) handleGet(w http.ResponseWriter, r *http.Request) {
	var req VolumeGetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		dp.sendError(w, fmt.Sprintf("decode request: %s", err))
		return
	}

	volume, err := dp.driver.Get(req.Name)
	if err != nil {
		resp := VolumeGetResponse{Err: err.Error()}
		dp.sendResponse(w, resp)
		return
	}

	dockerVolume := &DockerVolume{
		Name:       volume.Name,
		Mountpoint: volume.Path,
		Status:     map[string]interface{}{},
	}

	resp := VolumeGetResponse{Volume: dockerVolume}
	dp.sendResponse(w, resp)
}

// handleCapabilities handles capabilities requests.
func (dp *DockerPlugin) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	resp := CapabilitiesResponse{
		Capabilities: Capabilities{
			Scope: "global",
		},
	}
	dp.sendResponse(w, resp)
}

// sendResponse sends a JSON response.
func (dp *DockerPlugin) sendResponse(w http.ResponseWriter, response interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		dp.logger.Error("Failed to encode response", zap.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// sendError sends an error response.
func (dp *DockerPlugin) sendError(w http.ResponseWriter, errMsg string) {
	dp.logger.Error("Plugin error", zap.String("error", errMsg))
	resp := map[string]string{"Err": errMsg}
	dp.sendResponse(w, resp)
}