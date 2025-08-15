package storage

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	EnvsDisk = "/mnt/disks/fc-envs/v1"

	KernelsDir     = "/fc-kernels"
	KernelMountDir = "/fc-vm"
	KernelName     = "vmlinux.bin"

	HostEnvdPath  = "/fc-envd/envd"
	GuestEnvdPath = "/usr/bin/envd"

	FirecrackerVersionsDir = "/fc-versions"
	FirecrackerBinaryName  = "firecracker"

	JailerVersionsDir = "/jailer-versions"
	JailerBinaryName  = "jailer"

	buildDirName = "builds"

	MemfileName  = "memfile"
	RootfsName   = "rootfs.ext4"
	SnapfileName = "snapfile"
	MetadataName = "metadata.json"

	HeaderSuffix = ".header"
)

type TemplateFiles struct {
	TemplateID         string `json:"template_id"`
	BuildID            string `json:"build_id"`
	KernelVersion      string `json:"kernel_version"`
	FirecrackerVersion string `json:"firecracker_version"`
	JailerVersion      string `json:"jailer_version,omitempty"`
}

func (t TemplateFiles) BuildKernelPath() string {
	return filepath.Join(t.BuildKernelDir(), KernelName)
}

func (t TemplateFiles) BuildKernelDir() string {
	return filepath.Join(KernelMountDir, t.KernelVersion)
}

// Key for the cache. Unique for template-build pair.
func (t TemplateFiles) CacheKey() string {
	return fmt.Sprintf("%s-%s", t.TemplateID, t.BuildID)
}

func (t TemplateFiles) CacheKernelDir() string {
	return filepath.Join(KernelsDir, t.KernelVersion)
}

func (t TemplateFiles) CacheKernelPath() string {
	return filepath.Join(t.CacheKernelDir(), KernelName)
}

func (t TemplateFiles) FirecrackerPath() string {
	return filepath.Join(FirecrackerVersionsDir, t.FirecrackerVersion, FirecrackerBinaryName)
}

func (t TemplateFiles) JailerPath() string {
	// Use same version as Firecracker if JailerVersion not specified (backward compatibility)
	jailerVersion := t.JailerVersion
	if jailerVersion == "" {
		jailerVersion = t.FirecrackerVersion
		// Strip commit hash from Firecracker version (e.g., v1.12.1_d990331 → v1.12.1)
		// Jailer versions don't include commit hashes
		if idx := strings.Index(jailerVersion, "_"); idx != -1 {
			jailerVersion = jailerVersion[:idx]
		}
	}
	return filepath.Join(JailerVersionsDir, jailerVersion, JailerBinaryName)
}

func (t TemplateFiles) StorageDir() string {
	return t.BuildID
}

func (t TemplateFiles) StorageMemfilePath() string {
	return fmt.Sprintf("%s/%s", t.StorageDir(), MemfileName)
}

func (t TemplateFiles) StorageMemfileHeaderPath() string {
	return fmt.Sprintf("%s/%s%s", t.StorageDir(), MemfileName, HeaderSuffix)
}

func (t TemplateFiles) StorageRootfsPath() string {
	return fmt.Sprintf("%s/%s", t.StorageDir(), RootfsName)
}

func (t TemplateFiles) StorageRootfsHeaderPath() string {
	return fmt.Sprintf("%s/%s%s", t.StorageDir(), RootfsName, HeaderSuffix)
}

func (t TemplateFiles) StorageSnapfilePath() string {
	return fmt.Sprintf("%s/%s", t.StorageDir(), SnapfileName)
}

func (t TemplateFiles) StorageMetadataPath() string {
	return fmt.Sprintf("%s/%s", t.StorageDir(), MetadataName)
}

func (t TemplateFiles) SandboxBuildDir() string {
	return filepath.Join(EnvsDisk, t.TemplateID, buildDirName, t.BuildID)
}

func (t TemplateFiles) SandboxRootfsPath() string {
	return filepath.Join(t.SandboxBuildDir(), RootfsName)
}