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
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"
)

// Config defines volume driver configuration.
type Config struct {
	RootPath   string `yaml:"root_path"`
	DriverName string `yaml:"driver_name"`
}

// Driver manages Docker volume operations.
type Driver struct {
	config  Config
	logger  *zap.Logger
	volumes map[string]*Volume
	mutex   sync.RWMutex
}

// Volume represents a Docker volume.
type Volume struct {
	Name   string
	Path   string
	Driver string
	Labels map[string]string
}

// NewDriver creates a new volume driver.
func NewDriver(config Config, logger *zap.Logger) (*Driver, error) {
	// Ensure root path exists
	if err := os.MkdirAll(config.RootPath, 0755); err != nil {
		return nil, fmt.Errorf("create root path: %s", err)
	}

	return &Driver{
		config:  config,
		logger:  logger,
		volumes: make(map[string]*Volume),
	}, nil
}

// Start starts the volume driver.
func (d *Driver) Start() error {
	d.logger.Info("Starting volume driver",
		zap.String("root_path", d.config.RootPath),
		zap.String("driver_name", d.config.DriverName))
	return nil
}

// Stop stops the volume driver.
func (d *Driver) Stop() {
	d.logger.Info("Stopping volume driver")
}

// Create creates a new volume.
func (d *Driver) Create(name string, opts map[string]string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	volumePath := filepath.Join(d.config.RootPath, name)
	if err := os.MkdirAll(volumePath, 0755); err != nil {
		return fmt.Errorf("create volume directory: %s", err)
	}

	volume := &Volume{
		Name:   name,
		Path:   volumePath,
		Driver: d.config.DriverName,
		Labels: opts,
	}

	d.volumes[name] = volume
	d.logger.Info("Created volume", zap.String("name", name), zap.String("path", volumePath))
	return nil
}

// Remove removes a volume.
func (d *Driver) Remove(name string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	volume, exists := d.volumes[name]
	if !exists {
		return fmt.Errorf("volume not found: %s", name)
	}

	if err := os.RemoveAll(volume.Path); err != nil {
		return fmt.Errorf("remove volume directory: %s", err)
	}

	delete(d.volumes, name)
	d.logger.Info("Removed volume", zap.String("name", name))
	return nil
}

// Mount mounts a volume and returns the mount path.
func (d *Driver) Mount(name string, id string) (string, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	volume, exists := d.volumes[name]
	if !exists {
		return "", fmt.Errorf("volume not found: %s", name)
	}

	// For KrakenFS, the mount path is the same as the volume path
	// since we're doing file-level synchronization
	mountPath := filepath.Join(volume.Path, id)
	if err := os.MkdirAll(mountPath, 0755); err != nil {
		return "", fmt.Errorf("create mount directory: %s", err)
	}

	d.logger.Info("Mounted volume",
		zap.String("name", name),
		zap.String("id", id),
		zap.String("mount_path", mountPath))
	return mountPath, nil
}

// Unmount unmounts a volume.
func (d *Driver) Unmount(name string) error {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	_, exists := d.volumes[name]
	if !exists {
		return fmt.Errorf("volume not found: %s", name)
	}

	d.logger.Info("Unmounted volume", zap.String("name", name))
	return nil
}

// List returns all volumes.
func (d *Driver) List() ([]*Volume, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	volumes := make([]*Volume, 0, len(d.volumes))
	for _, volume := range d.volumes {
		volumes = append(volumes, volume)
	}
	return volumes, nil
}

// Get returns a specific volume.
func (d *Driver) Get(name string) (*Volume, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	volume, exists := d.volumes[name]
	if !exists {
		return nil, fmt.Errorf("volume not found: %s", name)
	}
	return volume, nil
}
