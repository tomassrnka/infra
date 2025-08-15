package fc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapio"

	"github.com/e2b-dev/infra/packages/orchestrator/internal/sandbox/network"
	"github.com/e2b-dev/infra/packages/orchestrator/internal/sandbox/template"
	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
	sbxlogger "github.com/e2b-dev/infra/packages/shared/pkg/logger/sandbox"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage"
	"github.com/e2b-dev/infra/packages/shared/pkg/telemetry"
	"github.com/e2b-dev/infra/packages/shared/pkg/utils"
)

type ProcessOptions struct {
	// InitScriptPath is the path to the init script that will be executed inside the VM on kernel start.
	InitScriptPath string

	// KernelLogs is a flag to enable kernel logs output to the process stdout.
	KernelLogs bool
	// SystemdToKernelLogs is a flag to enable systemd logs output to the console.
	// It enabled the kernel logs by default too.
	SystemdToKernelLogs bool

	// Stdout is the writer to which the process stdout will be written.
	Stdout io.Writer
	// Stderr is the writer to which the process stderr will be written.
	Stderr io.Writer
	
	// IsProvisionPhase indicates this is a provision VM that should exit after completion
	// Provision VMs use --daemonize so WaitForExit() can detect completion
	// Template build VMs disable --daemonize so parent can handle reboots
	IsProvisionPhase bool
}

// Process represents a Firecracker process managed by the jailer
// This replaces the original Process struct entirely
type Process struct {
	// Core fields
	slot       *network.Slot
	rootfsPath string
	files      *storage.SandboxFiles
	Exit       *utils.SetOnce[struct{}]
	
	// Process management (jailer in this implementation)
	cmd             *exec.Cmd
	jailRoot              string
	firecrackerSocketPath string
	jailSocketPath        string
	hostJailSocketPath    string
	firecrackerPidFile    string
	
	// API client
	client *apiClient
	buildRootfsPath string  // Keep for compatibility with original interface
}

// NewProcess creates a new Firecracker process using the jailer for isolation
// This replaces the original NewProcess function
func NewProcess(
	ctx context.Context,
	tracer trace.Tracer,
	slot *network.Slot,
	files *storage.SandboxFiles,
	rootfsPath string,
	baseTemplateID string,
	baseBuildID string,
) (*Process, error) {
	_, childSpan := tracer.Start(ctx, "initialize-fc", trace.WithAttributes(
		attribute.Int("sandbox.slot.index", slot.Idx),
		attribute.String("sandbox.isolation", "jailer"),
	))
	defer childSpan.End()

	// Verify required files exist
	if _, err := os.Stat(files.FirecrackerPath()); err != nil {
		return nil, fmt.Errorf("firecracker binary not found: %w", err)
	}
	
	if _, err := os.Stat(files.JailerPath()); err != nil {
		return nil, fmt.Errorf("jailer binary not found: %w", err)
	}
	
	if _, err := os.Stat(files.CacheKernelPath()); err != nil {
		return nil, fmt.Errorf("kernel file not found: %w", err)
	}

	// Calculate jail paths
	execName := filepath.Base(files.FirecrackerPath())
	jailRoot := filepath.Join("/srv/jailer", execName, files.SandboxID, "root")
	
	// Original E2B expected socket path - we need to make this accessible from jail
	expectedSocketPath := files.SandboxFirecrackerSocketPath()
	// Socket path inside jail that maps to the expected path on host
	// We'll use /run/firecracker.socket inside jail and bind mount to expected location
	jailSocketPath := "/run/firecracker.socket" // Path as seen from inside jail
	hostJailSocketPath := filepath.Join(jailRoot, "run", "firecracker.socket") // Host path to jail socket
	firecrackerPidFile := filepath.Join("/srv/jailer", execName, files.SandboxID, "firecracker.pid")

	// Set buildRootfsPath for compatibility
	baseBuild := storage.TemplateFiles{
		TemplateID:         baseTemplateID,
		BuildID:            baseBuildID,
		KernelVersion:      files.KernelVersion,
		FirecrackerVersion: files.FirecrackerVersion,
	}
	buildRootfsPath := baseBuild.SandboxRootfsPath()

	return &Process{
		Exit:                  utils.NewSetOnce[struct{}](),
		slot:                  slot,
		rootfsPath:            rootfsPath,
		files:                 files,
		jailRoot:              jailRoot,
		firecrackerSocketPath: expectedSocketPath,
		jailSocketPath:        jailSocketPath,
		hostJailSocketPath:    hostJailSocketPath,
		firecrackerPidFile:    firecrackerPidFile,
		client:                newApiClient(expectedSocketPath),
		buildRootfsPath:       buildRootfsPath,
	}, nil
}

// buildJailerCommand constructs the jailer command with all necessary arguments
func (p *Process) buildJailerCommand(isProvisionPhase bool) *exec.Cmd {
	// Build jailer arguments WITHOUT --netns flag
	// Jailer will inherit E2B's pre-configured network namespace
	jailerArgs := []string{
		"--id", p.files.SandboxID,
		"--exec-file", p.files.FirecrackerPath(),
		"--uid", "1000", // Unprivileged user
		"--gid", "1000",
		"--chroot-base-dir", "/srv/jailer",
		"--cgroup-version", "2",
		"--parent-cgroup", "firecracker",
		// NO --netns flag - inherit E2B's network namespace instead of creating new one
	}
	
	// Add --daemonize conditionally based on operation type:
	// - Provision phase: Use --daemonize so WaitForExit() can detect VM completion
	// - Template build: Disable --daemonize so parent can handle VM reboots
	if isProvisionPhase {
		jailerArgs = append(jailerArgs, "--daemonize")
	}
	
	// Add resource limits (can be made configurable later)
	jailerArgs = append(jailerArgs,
		"--resource-limit", "no-file=2048",
		// File size limit removed - templates can have dynamic sizes
	)

	// Add Firecracker arguments after "--"
	jailerArgs = append(jailerArgs, "--")
	// Use socket path as seen from inside jail
	jailerArgs = append(jailerArgs, "--api-sock", p.jailSocketPath)

	// Direct jailer execution - no ip netns exec wrapper needed
	// Network namespace will be inherited when this function is called from within E2B's namespace
	cmd := exec.Command(p.files.JailerPath(), jailerArgs...)
	
	// Ensure jail tmp directory exists for Firecracker logger
	jailTmpDir := filepath.Join(p.jailRoot, "tmp")
	if err := os.MkdirAll(jailTmpDir, 0755); err != nil {
		zap.L().Warn("failed to create jail tmp directory", zap.Error(err))
	} else if err := os.Chown(jailTmpDir, 1000, 1000); err != nil {
		zap.L().Warn("failed to set jail tmp ownership", zap.Error(err))
	}
	
	// Pre-create console log file for Firecracker logger
	consoleLogFile := fmt.Sprintf("vm-console-%s.log", p.files.SandboxID)
	hostConsoleLogPath := filepath.Join(jailTmpDir, consoleLogFile)
	if logFile, err := os.Create(hostConsoleLogPath); err != nil {
		zap.L().Warn("failed to create console log file", zap.Error(err))
	} else {
		logFile.Close() // Just create the file, Firecracker will write to it
		if err := os.Chown(hostConsoleLogPath, 1000, 1000); err != nil {
			zap.L().Warn("failed to set console log ownership", zap.Error(err))
		}
		zap.L().Info("pre-created console log file for Firecracker logger",
			zap.String("host_path", hostConsoleLogPath),
			zap.String("jail_path", fmt.Sprintf("/tmp/%s", consoleLogFile)))
	}
	
	zap.L().Info("jailer configured with E2B network namespace inheritance",
		zap.String("namespace", p.slot.NamespaceID()),
		zap.String("sandbox_id", p.files.SandboxID),
		zap.Strings("jailer_args", jailerArgs))

	return cmd
}


// prepareJailFiles ensures required files are accessible for the jail
func (p *Process) prepareJailFiles() error {
	// Create jail directories
	devDir := filepath.Join(p.jailRoot, "dev")
	if err := os.MkdirAll(devDir, 0755); err != nil {
		return fmt.Errorf("failed to create jail dev dir: %w", err)
	}

	// Create run directory for Firecracker socket
	runDir := filepath.Join(p.jailRoot, "run")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return fmt.Errorf("failed to create jail run dir: %w", err)
	}
	// Ensure it's owned by jailer user
	if err := os.Chown(runDir, 1000, 1000); err != nil {
		return fmt.Errorf("failed to set run dir ownership: %w", err)
	}

	// With ip netns exec wrapper, we don't need to bind mount the network namespace
	// The jailer and Firecracker will already be running within the namespace

	// Create the directory structure for E2B expected socket path
	expectedSocketDir := filepath.Dir(p.firecrackerSocketPath)
	if err := os.MkdirAll(expectedSocketDir, 0755); err != nil {
		return fmt.Errorf("failed to create expected socket directory: %w", err)
	}

	// Note: The jailer automatically creates /dev/net/tun inside the jail
	// We need to ensure the TAP interface created by E2B is properly accessible
	// within the network namespace for Firecracker to configure it

	// Handle kernel (always a file)
	jailKernel := filepath.Join(p.jailRoot, "kernel")
	os.Remove(jailKernel)
	
	// Try hard link first, then bind mount if cross-filesystem
	if err := os.Link(p.files.CacheKernelPath(), jailKernel); err != nil {
		// Hard link failed (likely cross-filesystem), create empty file and bind mount
		if err := os.WriteFile(jailKernel, nil, 0444); err != nil {
			return fmt.Errorf("failed to create kernel file in jail: %w", err)
		}
		
		// Bind mount the kernel file into the jail
		if err := syscall.Mount(p.files.CacheKernelPath(), jailKernel, "", syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("failed to bind mount kernel into jail: %w", err)
		}
	}
	os.Chmod(jailKernel, 0444)

	// Handle rootfs - can be NBD device or regular file
	if err := p.createNBDDeviceInJail(); err != nil {
		return fmt.Errorf("failed to create rootfs in jail: %w", err)
	}

	// CRITICAL FIX: Bind mount the actual rootfs file instead of using broken symlinks
	// The buildRootfsPath is what the template system expects to find
	jailBuildRootfsPath := filepath.Join(p.jailRoot, strings.TrimPrefix(p.buildRootfsPath, "/"))
	if err := os.MkdirAll(filepath.Dir(jailBuildRootfsPath), 0755); err != nil {
		return fmt.Errorf("failed to create build directory in jail: %w", err)
	}
	
	// Remove any existing file
	os.Remove(jailBuildRootfsPath)
	
	// Create empty file as bind mount target
	if err := os.WriteFile(jailBuildRootfsPath, []byte{}, 0644); err != nil {
		return fmt.Errorf("failed to create bind mount target: %w", err)
	}
	
	// Bind mount the actual rootfs file to the expected location
	// This ensures the rootfs is accessible at the expected path inside the jail
	if err := unix.Mount(p.rootfsPath, jailBuildRootfsPath, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("failed to bind mount rootfs into jail: %w", err)
	}
	
	// CRITICAL: Set correct ownership for the bind-mounted file
	// Firecracker runs as uid 1000 inside the jail and needs read access
	if err := os.Chown(jailBuildRootfsPath, 1000, 1000); err != nil {
		zap.L().Warn("failed to set rootfs ownership for jailer", 
			zap.Error(err), zap.String("path", jailBuildRootfsPath))
		// Continue anyway - the file might still be readable
	}
	
	// Ensure the file has read permissions
	if err := os.Chmod(jailBuildRootfsPath, 0644); err != nil {
		zap.L().Warn("failed to set rootfs permissions for jailer", 
			zap.Error(err), zap.String("path", jailBuildRootfsPath))
		// Continue anyway
	}
	
	zap.L().Info("bind mounted rootfs into jail with proper permissions", 
		zap.String("source", p.rootfsPath),
		zap.String("target", jailBuildRootfsPath))

	return nil
}

// copyFile copies a file from src to dst
func (p *Process) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// bindMountHostFileIntoJail bind mounts a host file into jail for zero-copy access
func (p *Process) bindMountHostFileIntoJail(hostPath, fileType string) (string, error) {
	// Create a unique filename inside jail for this snapshot file
	fileName := fmt.Sprintf("%s-%s", fileType, p.files.SandboxID)
	jailPath := filepath.Join(p.jailRoot, fileName)
	
	zap.L().Info("setting up zero-copy bind mount for snapshot file",
		zap.String("host_path", hostPath),
		zap.String("jail_path", jailPath),
		zap.String("file_type", fileType))
	
	// Ensure the host directory exists
	if err := os.MkdirAll(filepath.Dir(hostPath), 0755); err != nil {
		return "", fmt.Errorf("failed to create host directory for %s: %w", fileType, err)
	}
	
	// Only create empty file if it doesn't exist (for CreateSnapshot)
	// For Resume/LoadSnapshot, the file already exists and should not be truncated
	if _, err := os.Stat(hostPath); os.IsNotExist(err) {
		// Create empty file at the original host path for Firecracker to write to
		if err := os.WriteFile(hostPath, []byte{}, 0644); err != nil {
			return "", fmt.Errorf("failed to create host file for %s: %w", fileType, err)
		}
	}
	
	// Remove any existing jail file
	os.Remove(jailPath)
	
	// Create empty file as bind mount target in jail
	if err := os.WriteFile(jailPath, []byte{}, 0644); err != nil {
		return "", fmt.Errorf("failed to create jail bind target for %s: %w", fileType, err)
	}
	
	// Bind mount the host file into the jail
	if err := unix.Mount(hostPath, jailPath, "", unix.MS_BIND, ""); err != nil {
		return "", fmt.Errorf("failed to bind mount %s into jail: %w", fileType, err)
	}
	
	// Set correct ownership for jailer (uid 1000) 
	if err := os.Chown(jailPath, 1000, 1000); err != nil {
		zap.L().Warn("failed to set snapshot file ownership for jailer", 
			zap.Error(err), zap.String("path", jailPath), zap.String("file_type", fileType))
		// Continue anyway - the file might still be writable
	}
	
	// Ensure the file has write permissions for jailer
	if err := os.Chmod(jailPath, 0644); err != nil {
		zap.L().Warn("failed to set snapshot file permissions for jailer", 
			zap.Error(err), zap.String("path", jailPath), zap.String("file_type", fileType))
		// Continue anyway
	}
	
	// Return the jail-relative path (what Firecracker will see)
	jailRelativePath := strings.TrimPrefix(jailPath, p.jailRoot+"/")
	
	zap.L().Info("successfully set up zero-copy bind mount for snapshot file",
		zap.String("host_path", hostPath),
		zap.String("jail_path", jailPath),
		zap.String("jail_relative_path", jailRelativePath),
		zap.String("file_type", fileType))
	
	return jailRelativePath, nil
}

// createNBDDeviceInJail creates the NBD device node or copies file inside the jail
func (p *Process) createNBDDeviceInJail() error {
	// Get file info to determine if it's a block device or regular file
	var stat syscall.Stat_t
	if err := syscall.Stat(p.rootfsPath, &stat); err != nil {
		return fmt.Errorf("failed to stat rootfs %s: %w", p.rootfsPath, err)
	}

	// Create the same path in jail
	jailPath := filepath.Join(p.jailRoot, p.rootfsPath[1:]) // Remove leading /
	jailDir := filepath.Dir(jailPath)
	
	if err := os.MkdirAll(jailDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory in jail: %w", err)
	}

	// Remove existing file/device if present
	os.Remove(jailPath)

	// Check if it's a block device (NBD) or regular file
	if (stat.Mode & syscall.S_IFMT) == syscall.S_IFBLK {
		// It's a block device - create device node with same major/minor numbers
		major := uint64(stat.Rdev >> 8)
		minor := uint64(stat.Rdev & 0xff)
		dev := unix.Mkdev(uint32(major), uint32(minor))
		
		if err := syscall.Mknod(jailPath, syscall.S_IFBLK|0660, int(dev)); err != nil {
			return fmt.Errorf("failed to create device node %s: %w", jailPath, err)
		}

		// Set correct ownership
		if err := os.Chown(jailPath, 1000, 1000); err != nil {
			return fmt.Errorf("failed to set device ownership: %w", err)
		}
	} else {
		// It's a regular file - use hard link first, then bind mount (never copy large files!)
		if err := os.Link(p.rootfsPath, jailPath); err != nil {
			// Hard link failed (likely cross-filesystem), create empty file and bind mount
			if err := os.WriteFile(jailPath, nil, 0644); err != nil {
				return fmt.Errorf("failed to create rootfs bind target in jail: %w", err)
			}
			
			// Bind mount the rootfs file into the jail
			if err := unix.Mount(p.rootfsPath, jailPath, "", unix.MS_BIND, ""); err != nil {
				return fmt.Errorf("failed to bind mount rootfs into jail: %w", err)
			}
		}

		// Set correct ownership and permissions
		if err := os.Chown(jailPath, 1000, 1000); err != nil {
			return fmt.Errorf("failed to set file ownership: %w", err)
		}
		if err := os.Chmod(jailPath, 0644); err != nil {
			return fmt.Errorf("failed to set file permissions: %w", err)
		}
	}

	return nil
}

// copyDeviceNode creates a device node in the jail with the same major/minor numbers
func (p *Process) copyDeviceNode(srcPath, dstPath string) error {
	// Get device info from source
	var stat syscall.Stat_t
	if err := syscall.Stat(srcPath, &stat); err != nil {
		return fmt.Errorf("failed to stat device %s: %w", srcPath, err)
	}

	// Remove existing device if present
	os.Remove(dstPath)

	// Create device node with same major/minor numbers
	major := uint64(stat.Rdev >> 8)
	minor := uint64(stat.Rdev & 0xff)
	dev := unix.Mkdev(uint32(major), uint32(minor))
	
	if err := syscall.Mknod(dstPath, stat.Mode, int(dev)); err != nil {
		return fmt.Errorf("failed to create device node %s: %w", dstPath, err)
	}

	// Set correct ownership for jailer user
	if err := os.Chown(dstPath, 1000, 1000); err != nil {
		return fmt.Errorf("failed to set device ownership: %w", err)
	}

	// Set appropriate permissions for TUN device
	if err := os.Chmod(dstPath, 0666); err != nil {
		return fmt.Errorf("failed to set device permissions: %w", err)
	}

	return nil
}

// configure sets up and starts the jailed Firecracker process
func (p *Process) configure(
	ctx context.Context,
	tracer trace.Tracer,
	sandboxID string,
	templateID string,
	teamID string,
	stdoutExternal io.Writer,
	stderrExternal io.Writer,
) error {
	childCtx, childSpan := tracer.Start(ctx, "configure-fc")
	defer childSpan.End()

	sbxMetadata := sbxlogger.SandboxMetadata{
		SandboxID:  sandboxID,
		TemplateID: templateID,
		TeamID:     teamID,
	}

	// Setup logging
	stdoutWriter := &zapio.Writer{Log: sbxlogger.I(sbxMetadata).Logger, Level: zap.InfoLevel}
	stderrWriter := &zapio.Writer{Log: sbxlogger.I(sbxMetadata).Logger, Level: zap.ErrorLevel}

	// Prepare jail files
	if err := p.prepareJailFiles(); err != nil {
		return fmt.Errorf("failed to prepare jail files: %w", err)
	}


	// Create TAP device in network namespace and start jailer
	// Jailer will handle network namespace joining via --netns argument
	stderrBuf, err := p.setupNetworkAndStartJailer(childCtx, stdoutExternal, stderrExternal)
	if err != nil {
		return fmt.Errorf("failed to setup network and start jailer: %w", err)
	}

	zap.L().Info("jailer process started", 
		zap.Int("pid", p.cmd.Process.Pid),
		zap.String("socket_path_expected", p.firecrackerSocketPath))

	startCtx, cancelStart := context.WithCancelCause(childCtx)
	defer cancelStart(fmt.Errorf("fc finished starting"))

	// Monitor jailer process in background 
	go func(stderrContent *bytes.Buffer) {
		defer stderrWriter.Close()
		defer stdoutWriter.Close()

		waitErr := p.cmd.Wait()
		
		// Log stderr content to diagnose why Firecracker failed to start
		stderrStr := stderrContent.String()
		
		if waitErr != nil {
			zap.L().Error("jailer parent process exited with error", 
				zap.String("exit_reason", waitErr.Error()),
				zap.String("stderr", stderrStr),
				zap.String("sandbox_id", p.files.SandboxID))
			
			// Jailer setup failed - signal error to Exit mechanism
			p.Exit.SetError(fmt.Errorf("jailer setup failed: %w", waitErr))
			cancelStart(waitErr)
			return
		} else {
			zap.L().Info("jailer parent process exited cleanly - VM has shut down", 
				zap.String("stderr", stderrStr),
				zap.String("sandbox_id", p.files.SandboxID))
			
			// Signal that the VM has exited (successful termination)
			p.Exit.SetValue(struct{}{})
			zap.L().Info("signaled VM exit to WaitForExit()", 
				zap.String("sandbox_id", p.files.SandboxID))
		}
	}(stderrBuf)

	// Wait directly for Firecracker socket - much simpler approach
	socketCtx, socketCancel := context.WithTimeout(startCtx, 30*time.Second)
	defer socketCancel()
	
	err = p.waitForSocketAndCreateLink(socketCtx)
	if err != nil {
		// Log diagnostic information
		zap.L().Error("Firecracker socket not available after 30s", 
			zap.Error(err),
			zap.String("sandbox_id", p.files.SandboxID),
			zap.String("jail_root", p.jailRoot),
			zap.String("expected_socket", p.firecrackerSocketPath))
		
		// Check if jailer process is still running
		if p.cmd.Process != nil {
			zap.L().Error("jailer process still running", 
				zap.Int("pid", p.cmd.Process.Pid))
		}
		
		return fmt.Errorf("error waiting for firecracker socket: %w", err)
	}
	
	zap.L().Info("Firecracker socket ready", 
		zap.String("sandbox_id", p.files.SandboxID))

	// VM console output capture is now handled via Firecracker logger API


	return nil
}

// waitForSocketAndCreateLink waits for the Firecracker API socket to become available inside the jail
// and creates a symlink to the expected E2B location
func (p *Process) waitForSocketAndCreateLink(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	zap.L().Info("waiting for firecracker socket in jail", 
		zap.String("jail_socket_path", p.hostJailSocketPath),
		zap.String("expected_socket_path", p.firecrackerSocketPath))

	for {
		select {
		case <-ctx.Done():
			// Log final state before giving up
			if _, err := os.Stat(p.hostJailSocketPath); err != nil {
				zap.L().Error("jail socket not found when timeout occurred", 
					zap.String("jail_socket_path", p.hostJailSocketPath),
					zap.Error(err))
			}
			if _, err := os.Stat(p.firecrackerSocketPath); err != nil {
				zap.L().Error("expected socket not found when timeout occurred", 
					zap.String("expected_socket_path", p.firecrackerSocketPath),
					zap.Error(err))
			}
			return ctx.Err()
		case <-ticker.C:
			if _, err := os.Stat(p.hostJailSocketPath); err == nil {
				// Socket exists in jail, create symlink to expected location
				zap.L().Info("firecracker socket found in jail", zap.String("jail_socket_path", p.hostJailSocketPath))
				
				// Remove any existing socket at expected path
				os.Remove(p.firecrackerSocketPath)
				
				// Create symlink from expected path to jail socket
				if err := os.Symlink(p.hostJailSocketPath, p.firecrackerSocketPath); err != nil {
					return fmt.Errorf("failed to create socket symlink: %w", err)
				}
				
				zap.L().Info("created socket symlink", 
					zap.String("from", p.firecrackerSocketPath),
					zap.String("to", p.hostJailSocketPath))
				
				return nil
			}
		}
	}
}

// Create creates and starts the Firecracker VM
func (p *Process) Create(
	ctx context.Context,
	tracer trace.Tracer,
	sandboxID string,
	templateID string,
	teamID string,
	vCPUCount int64,
	memoryMB int64,
	hugePages bool,
	options ProcessOptions,
) error {
	childCtx, childSpan := tracer.Start(ctx, "create-fc")
	defer childSpan.End()

	// Add cgroup settings for resource limits
	if memoryMB > 0 || vCPUCount > 0 {
		// Rebuild command with resource limits
		p.cmd = p.buildJailerCommandWithResources(vCPUCount, memoryMB, options.IsProvisionPhase)
	} else {
		// Build basic command
		p.cmd = p.buildJailerCommand(options.IsProvisionPhase)
	}

	err := p.configure(
		childCtx,
		tracer,
		sandboxID,
		templateID,
		teamID,
		options.Stdout,
		options.Stderr,
	)
	if err != nil {
		fcStopErr := p.Stop()
		return errors.Join(fmt.Errorf("error starting fc process: %w", err), fcStopErr)
	}

	// Configure kernel boot args (same as original)
	// IPv4 configuration - format: [local_ip]::[gateway_ip]:[netmask]:hostname:iface:dhcp_option:[dns]
	ipv4 := fmt.Sprintf("%s::%s:%s:instance:%s:off:%s", 
		p.slot.NamespaceIP(), p.slot.TapIPString(), p.slot.TapMaskString(), 
		p.slot.VpeerName(), p.slot.TapName())
	
	// Debug: Log the init script path being used
	zap.L().Info("configuring VM boot with init script", 
		zap.String("init_script", options.InitScriptPath),
		zap.String("ipv4_config", ipv4))

	args := KernelArgs{
		// RESTORE ORIGINAL: Use quiet and loglevel=1 like original E2B
		"quiet":    "",
		"loglevel": "1",

		// Define kernel init path
		"init": options.InitScriptPath,

		// Networking IPv4 and IPv6
		"ip":            ipv4,
		"ipv6.disable":  "0",
		"ipv6.autoconf": "1",

		// Wait 1 second before exiting FC after panic or reboot
		"panic": "1",

		"reboot":           "k",
		"pci":              "off",
		"i8042.nokbd":      "",
		"i8042.noaux":      "",
		"random.trust_cpu": "on",
	}

	if options.SystemdToKernelLogs {
		args["systemd.journald.forward_to_console"] = ""
	}
	if options.KernelLogs || options.SystemdToKernelLogs {
		delete(args, "quiet")
		args["console"] = "ttyS0"
		args["loglevel"] = "5"
	}

	// Configure Firecracker via API - use correct paths for jail
	err = p.client.setBootSource(childCtx, args.String(), "kernel")
	if err != nil {
		fcStopErr := p.Stop()
		return errors.Join(fmt.Errorf("error setting fc boot source config: %w", err), fcStopErr)
	}
	telemetry.ReportEvent(childCtx, "set fc boot source config")

	// Use buildRootfsPath - this is the bind-mounted rootfs file inside the jail
	// The jailer sees this as the path relative to the jail root
	jailRootfsPath := strings.TrimPrefix(p.buildRootfsPath, "/")
	zap.L().Info("configuring Firecracker rootfs drive", 
		zap.String("jail_rootfs_path", jailRootfsPath),
		zap.String("original_rootfs_path", p.rootfsPath))
	
	err = p.client.setRootfsDrive(childCtx, jailRootfsPath)
	if err != nil {
		fcStopErr := p.Stop()
		return errors.Join(fmt.Errorf("error setting fc drivers config: %w", err), fcStopErr)
	}
	telemetry.ReportEvent(childCtx, "set fc drivers config")

	// Add debugging to verify TAP device before configuring Firecracker
	tapName := p.slot.TapName()
	zap.L().Info("about to configure Firecracker network interface", 
		zap.String("tap_name", tapName),
		zap.String("vpeer_name", p.slot.VpeerName()),
		zap.String("tap_mac", p.slot.TapMAC()),
		zap.String("sandbox_id", p.files.SandboxID))

	err = p.client.setNetworkInterface(childCtx, p.slot.VpeerName(), tapName, p.slot.TapMAC())
	if err != nil {
		// Enhanced error logging for TAP configuration failures
		zap.L().Error("failed to configure Firecracker network interface", 
			zap.Error(err),
			zap.String("tap_name", tapName),
			zap.String("vpeer_name", p.slot.VpeerName()),
			zap.String("tap_mac", p.slot.TapMAC()),
			zap.String("sandbox_id", p.files.SandboxID))
		fcStopErr := p.Stop()
		return errors.Join(fmt.Errorf("error setting fc network config: %w", err), fcStopErr)
	}
	telemetry.ReportEvent(childCtx, "set fc network config")

	err = p.client.setMachineConfig(childCtx, vCPUCount, memoryMB, hugePages)
	if err != nil {
		fcStopErr := p.Stop()
		return errors.Join(fmt.Errorf("error setting fc machine config: %w", err), fcStopErr)
	}
	telemetry.ReportEvent(childCtx, "set fc machine config")

	// Configure Firecracker logger to capture VM console output inside jail
	loggerPath := fmt.Sprintf("/tmp/vm-console-%s.log", p.files.SandboxID)
	err = p.client.setLogger(childCtx, loggerPath)
	if err != nil {
		fcStopErr := p.Stop()
		return errors.Join(fmt.Errorf("error setting fc logger config: %w", err), fcStopErr)
	}
	zap.L().Info("configured Firecracker logger for VM console capture",
		zap.String("jail_path", loggerPath),
		zap.String("host_path", filepath.Join(p.jailRoot, "tmp", fmt.Sprintf("vm-console-%s.log", p.files.SandboxID))))
	telemetry.ReportEvent(childCtx, "set fc logger config")

	err = p.client.startVM(childCtx)
	if err != nil {
		fcStopErr := p.Stop()
		return errors.Join(fmt.Errorf("error starting fc: %w", err), fcStopErr)
	}

	telemetry.ReportEvent(childCtx, "started fc")
	return nil
}

// buildJailerCommandWithResources builds command with resource limits
func (p *Process) buildJailerCommandWithResources(vCPUCount, memoryMB int64, isProvisionPhase bool) *exec.Cmd {
	cmd := p.buildJailerCommand(isProvisionPhase)
	
	// Insert cgroup settings before the "--" separator
	args := cmd.Args[1:] // Skip the command name
	newArgs := []string{p.files.JailerPath()}
	
	separatorIdx := -1
	for i, arg := range args {
		if arg == "--" {
			separatorIdx = i
			break
		}
	}

	// Add args before separator
	if separatorIdx > 0 {
		newArgs = append(newArgs, args[:separatorIdx]...)
	} else {
		newArgs = append(newArgs, args...)
	}

	// Add resource limits
	if memoryMB > 0 {
		memoryBytes := memoryMB * 1024 * 1024
		newArgs = append(newArgs, "--cgroup", fmt.Sprintf("memory.max=%d", memoryBytes))
	}

	if vCPUCount > 0 {
		cpuQuota := vCPUCount * 100000 // 100% of one core = 100000 microseconds
		newArgs = append(newArgs, "--cgroup", fmt.Sprintf("cpu.max=%d 100000", cpuQuota))
	}

	// Add separator and remaining args
	if separatorIdx > 0 {
		newArgs = append(newArgs, args[separatorIdx:]...)
	}

	cmd = exec.Command(newArgs[0], newArgs[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	return cmd
}

// Resume resumes a VM from snapshot
func (p *Process) Resume(
	ctx context.Context,
	tracer trace.Tracer,
	mmdsMetadata *MmdsMetadata,
	uffdSocketPath string,
	snapfile template.File,
	uffdReady chan struct{},
) error {
	childCtx, childSpan := tracer.Start(ctx, "resume-fc")
	defer childSpan.End()

	err := p.configure(
		childCtx,
		tracer,
		mmdsMetadata.SandboxId,
		mmdsMetadata.TemplateId,
		mmdsMetadata.TeamId,
		nil,
		nil,
	)
	if err != nil {
		fcStopErr := p.Stop()
		return errors.Join(fmt.Errorf("error starting fc process: %w", err), fcStopErr)
	}

	// For jailer, wait for jail directory structure to be ready after jailer starts
	if p.jailRoot != "" {
		if err := p.waitForJailDirectory(childCtx); err != nil {
			fcStopErr := p.Stop()
			return errors.Join(fmt.Errorf("failed to wait for jail directory: %w", err), fcStopErr)
		}
	}

	// For jailer implementation, we bind mount host snapfile into jail for LoadSnapshot
	// This allows Firecracker to read the snapshot file from the original host path
	jailSnapfilePath, err := p.bindMountHostFileIntoJail(snapfile.Path(), "snapfile")
	if err != nil {
		fcStopErr := p.Stop()
		return errors.Join(fmt.Errorf("failed to bind mount snapfile for resume: %w", err), fcStopErr)
	}
	
	// Handle UFFD socket paths for jailer
	jailUffdSocketPath := uffdSocketPath      // jail-internal path for Firecracker API
	waitUffdSocketPath := uffdSocketPath      // jail-aware path for orchestrator to wait on
	
	if p.jailRoot != "" {
		jailUffdSocketPath = p.GetJailUffdSocketPath()        // /tmp/uffd-{id}.sock (for Firecracker)
		waitUffdSocketPath = p.GetJailAwareUffdSocketPath()   // /srv/jailer/.../tmp/uffd-{id}.sock (for orchestrator)
		zap.L().Info("UFFD socket paths for jailer",
			zap.String("jail_internal_path", jailUffdSocketPath),
			zap.String("jail_aware_path", waitUffdSocketPath),
			zap.String("sandbox_id", p.files.SandboxID))
	}
	
	zap.L().Info("resume paths configured for jailer",
		zap.String("host_snapfile", snapfile.Path()),
		zap.String("jail_snapfile", jailSnapfilePath),
		zap.String("wait_uffd_socket", waitUffdSocketPath),
		zap.String("api_uffd_socket", jailUffdSocketPath))
	
	// Only load snapshot if UFFD is ready (two-phase loading support)
	if uffdReady != nil {
		err = p.client.loadSnapshotWithPaths(childCtx, waitUffdSocketPath, jailUffdSocketPath, uffdReady, jailSnapfilePath)
		if err != nil {
			fcStopErr := p.Stop()
			return errors.Join(fmt.Errorf("error loading snapshot: %w", err), fcStopErr)
		}
	} else {
		zap.L().Info("skipping snapshot load - UFFD will be connected later", 
			zap.String("sandbox_id", p.files.SandboxID))
	}

	err = p.client.resumeVM(childCtx)
	if err != nil {
		fcStopErr := p.Stop()
		return errors.Join(fmt.Errorf("error resuming vm: %w", err), fcStopErr)
	}

	err = p.client.setMmds(childCtx, mmdsMetadata)
	if err != nil {
		fcStopErr := p.Stop()
		return errors.Join(fmt.Errorf("error setting mmds: %w", err), fcStopErr)
	}

	return nil
}

// SetupJailDirectories creates jail directories and starts jailer synchronously  
// This is FAST - just creates directories and starts Firecracker, then returns immediately
func (p *Process) SetupJailDirectories(
	ctx context.Context,
	tracer trace.Tracer,
	sandboxID string,
	templateID string,
	teamID string,
) error {
	return p.configure(ctx, tracer, sandboxID, templateID, teamID, nil, nil)
}

// ResumeWithExistingJailer completes the resume when jailer is already running
// This handles snapshot loading and VM resume with UFFD coordination
func (p *Process) ResumeWithExistingJailer(
	ctx context.Context,
	tracer trace.Tracer,
	mmdsMetadata *MmdsMetadata,
	uffdSocketPath string,
	snapfile template.File,
	uffdReady chan struct{},
) error {
	childCtx, childSpan := tracer.Start(ctx, "resume-with-existing-jailer")
	defer childSpan.End()

	// Jail directories should already exist from SetupJailDirectories
	// But add a quick check to be safe
	if p.jailRoot != "" {
		jailTmpDir := filepath.Join(p.jailRoot, "tmp")
		if _, err := os.Stat(jailTmpDir); err != nil {
			return fmt.Errorf("jail tmp directory not ready: %s: %w", jailTmpDir, err)
		}
	}

	// Bind mount snapshot file into jail for LoadSnapshot
	jailSnapfilePath, err := p.bindMountHostFileIntoJail(snapfile.Path(), "snapfile")
	if err != nil {
		return fmt.Errorf("failed to bind mount snapfile for resume: %w", err)
	}
	
	// Handle UFFD socket paths for jailer
	jailUffdSocketPath := uffdSocketPath      // jail-internal path for Firecracker API
	waitUffdSocketPath := uffdSocketPath      // jail-aware path for orchestrator to wait on
	
	if p.jailRoot != "" {
		jailUffdSocketPath = p.GetJailUffdSocketPath()        // /tmp/uffd-{id}.sock (for Firecracker)
		waitUffdSocketPath = p.GetJailAwareUffdSocketPath()   // /srv/jailer/.../tmp/uffd-{id}.sock (for orchestrator)
		zap.L().Info("UFFD socket paths for jailer",
			zap.String("jail_internal_path", jailUffdSocketPath),
			zap.String("jail_aware_path", waitUffdSocketPath),
			zap.String("sandbox_id", p.files.SandboxID))
	}
	
	zap.L().Info("resume paths configured for jailer",
		zap.String("host_snapfile", snapfile.Path()),
		zap.String("jail_snapfile", jailSnapfilePath),
		zap.String("wait_uffd_socket", waitUffdSocketPath),
		zap.String("api_uffd_socket", jailUffdSocketPath))
	
	// Verify UFFD socket exists at the jail-aware path that orchestrator will wait on
	if _, err := os.Stat(waitUffdSocketPath); err != nil {
		zap.L().Error("UFFD socket not found at wait path", 
			zap.String("wait_path", waitUffdSocketPath),
			zap.Error(err))
	} else {
		zap.L().Info("UFFD socket exists at wait path", 
			zap.String("wait_path", waitUffdSocketPath))
	}
	
	// Load snapshot - this should be FAST since everything is ready
	// DON'T call Stop() here - let jailer complete startup first
	// Debug: Check what files actually exist in the jail
	zap.L().Info("jail contents before snapshot load")
	if entries, err := os.ReadDir(p.jailRoot); err == nil {
		for _, entry := range entries {
			zap.L().Info("jail root entry", zap.String("name", entry.Name()), zap.Bool("is_dir", entry.IsDir()))
		}
	}
	if entries, err := os.ReadDir(filepath.Join(p.jailRoot, "tmp")); err == nil {
		for _, entry := range entries {
			zap.L().Info("jail tmp entry", zap.String("name", entry.Name()), zap.Bool("is_dir", entry.IsDir()))
		}
	}
	
	// Check if Firecracker socket exists (should appear when FC starts)
	fcSocketPath := filepath.Join(p.jailRoot, "run", "firecracker.socket")
	if _, err := os.Stat(fcSocketPath); err != nil {
		zap.L().Warn("Firecracker socket not found", zap.String("path", fcSocketPath), zap.Error(err))
	} else {
		zap.L().Info("Firecracker socket exists", zap.String("path", fcSocketPath))
	}
	
	zap.L().Info("starting snapshot load", 
		zap.String("jail_uffd_socket", jailUffdSocketPath),
		zap.String("jail_snapfile", jailSnapfilePath),
		zap.String("sandbox_id", p.files.SandboxID))
		
	err = p.client.loadSnapshotWithPaths(childCtx, waitUffdSocketPath, jailUffdSocketPath, uffdReady, jailSnapfilePath)
	if err != nil {
		zap.L().Error("loadSnapshot failed", 
			zap.Error(err),
			zap.String("jail_uffd_socket", jailUffdSocketPath),
			zap.String("sandbox_id", p.files.SandboxID))
		return fmt.Errorf("error loading snapshot: %w", err)
	}
	
	zap.L().Info("snapshot loaded successfully", 
		zap.String("sandbox_id", p.files.SandboxID))

	// Resume VM - this should be FAST 
	err = p.client.resumeVM(childCtx)
	if err != nil {
		return fmt.Errorf("error resuming vm: %w", err)
	}

	// Set metadata - this should be FAST
	err = p.client.setMmds(childCtx, mmdsMetadata)
	if err != nil {
		return fmt.Errorf("error setting mmds: %w", err)
	}

	return nil
}

// GetJailAwareUffdSocketPath returns the path where UFFD socket should be created
// for jailer compatibility. Returns the external path where UFFD process creates it.
func (p *Process) GetJailAwareUffdSocketPath() string {
	// Check if jailer is being used
	if _, err := os.Stat("/jailer-versions/v1.12.1_d990331/jailer"); err != nil {
		// Jailer not available, use standard path
		return p.files.SandboxUffdSocketPath()
	}
	
	// CORRECT SOLUTION: Create socket directly in jail's /tmp directory structure
	return filepath.Join("/srv/jailer/firecracker", p.files.SandboxID, "root", "tmp", fmt.Sprintf("uffd-%s.sock", p.files.SandboxID))
}

// GetJailUffdSocketPath returns the path inside the jail where Firecracker will access the UFFD socket
func (p *Process) GetJailUffdSocketPath() string {
	// Check if jailer is being used
	if _, err := os.Stat("/jailer-versions/v1.12.1_d990331/jailer"); err != nil {
		// Jailer not available, use standard path
		return p.files.SandboxUffdSocketPath()
	}
	
	// From inside jail, the socket appears at /tmp/uffd-xxx.sock
	return filepath.Join("/tmp", fmt.Sprintf("uffd-%s.sock", p.files.SandboxID))
}

// PrepareUffdSocket ensures UFFD socket directory exists without interfering with jailer
// This must be called before starting UFFD process for Resume operations  
func (p *Process) PrepareUffdSocket() error {
	// Check if jailer is being used
	if _, err := os.Stat("/jailer-versions/v1.12.1_d990331/jailer"); err != nil {
		// Jailer not available, no special preparation needed
		return nil
	}
	
	// For jailer, we'll wait for the jail structure to be created and then ensure run dir exists
	// This is handled in waitForJailAndPrepareUffdSocket called after jailer starts
	
	zap.L().Info("prepared UFFD socket location for jailer",
		zap.String("socket_path", p.GetJailAwareUffdSocketPath()),
		zap.String("sandbox_id", p.files.SandboxID))
	
	return nil
}

// waitForJailAndPrepareUffdSocket waits for jailer to create directory structure then prepares UFFD socket directory
func (p *Process) waitForJailAndPrepareUffdSocket(ctx context.Context) error {
	jailRunDir := filepath.Join("/srv/jailer/firecracker", p.files.SandboxID, "root", "run")
	
	// Wait for jailer to create the jail structure
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for jail directory: %w", ctx.Err())
		case <-ticker.C:
			// Check if jail root exists (created by jailer)
			jailRoot := filepath.Join("/srv/jailer/firecracker", p.files.SandboxID, "root")
			if _, err := os.Stat(jailRoot); err != nil {
				continue // Jail not ready yet
			}
			
			// Jail exists, now ensure run directory exists for UFFD socket
			if err := os.MkdirAll(jailRunDir, 0755); err != nil {
				return fmt.Errorf("failed to create run directory in jail: %w", err)
			}
			
			// Set appropriate ownership
			if err := os.Chown(jailRunDir, 1000, 1000); err != nil {
				zap.L().Warn("failed to set ownership on jail run directory", zap.Error(err))
			}
			
			zap.L().Info("jail directory structure ready for UFFD socket",
				zap.String("jail_run_dir", jailRunDir),
				zap.String("sandbox_id", p.files.SandboxID))
			
			return nil
		}
	}
}

// LoadSnapshotAfterUffd loads snapshot after UFFD is ready (for two-phase loading)
func (p *Process) LoadSnapshotAfterUffd(
	ctx context.Context,
	tracer trace.Tracer,
	uffdSocketPath string,
	snapfile template.File,
	uffdReady chan struct{},
) error {
	childCtx, childSpan := tracer.Start(ctx, "load-snapshot-after-uffd")
	defer childSpan.End()

	// Get jail paths for snapfile and UFFD socket  
	jailSnapfilePath, err := p.bindMountHostFileIntoJail(snapfile.Path(), "snapfile")
	if err != nil {
		return fmt.Errorf("failed to bind mount snapfile: %w", err)
	}

	// Handle UFFD socket paths for jailer
	jailUffdSocketPath := uffdSocketPath      // jail-internal path for Firecracker API
	waitUffdSocketPath := uffdSocketPath      // jail-aware path for orchestrator to wait on
	
	if p.jailRoot != "" {
		jailUffdSocketPath = p.GetJailUffdSocketPath()        // /tmp/uffd-{id}.sock (for Firecracker)
		waitUffdSocketPath = p.GetJailAwareUffdSocketPath()   // /srv/jailer/.../tmp/uffd-{id}.sock (for orchestrator)
	}

	zap.L().Info("loading snapshot with UFFD after jailer setup",
		zap.String("jail_snapfile", jailSnapfilePath),
		zap.String("wait_uffd_socket", waitUffdSocketPath),
		zap.String("api_uffd_socket", jailUffdSocketPath),
		zap.String("sandbox_id", p.files.SandboxID))

	return p.client.loadSnapshotWithPaths(childCtx, waitUffdSocketPath, jailUffdSocketPath, uffdReady, jailSnapfilePath)
}

// waitForJailDirectory waits for jailer to create the jail directory structure
func (p *Process) waitForJailDirectory(ctx context.Context) error {
	jailTmpDir := filepath.Join("/srv/jailer/firecracker", p.files.SandboxID, "root", "tmp")
	
	// Wait for jailer to create the jail structure with timeout
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	
	timeout := time.After(5 * time.Second) // 5 second timeout
	
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled while waiting for jail directory: %w", ctx.Err())
		case <-timeout:
			return fmt.Errorf("timeout waiting for jail directory to be created")
		case <-ticker.C:
			// Check if jail /tmp directory exists (created by jailer)
			if _, err := os.Stat(jailTmpDir); err != nil {
				continue // Jail not ready yet
			}
			
			// Directory exists, we're ready
			zap.L().Info("jail directory structure ready",
				zap.String("jail_tmp_dir", jailTmpDir),
				zap.String("sandbox_id", p.files.SandboxID))
			
			return nil
		}
	}
}

// bindMountUffdSocketIntoJail waits for the UFFD socket and bind mounts it into jail's /tmp
func (p *Process) bindMountUffdSocketIntoJail(ctx context.Context, hostSocketPath string) error {
	// Wait for UFFD socket to be created on host
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for UFFD socket: %w", ctx.Err())
		case <-ticker.C:
			if _, err := os.Stat(hostSocketPath); err != nil {
				continue // Socket not ready yet
			}
			goto bindMount // Socket exists, proceed
		}
	}
	
bindMount:
	// Ensure jail's /tmp directory exists
	jailTmpDir := filepath.Join(p.jailRoot, "tmp")
	if err := os.MkdirAll(jailTmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create jail tmp directory: %w", err)
	}
	
	// Bind mount target path in jail
	jailSocketPath := filepath.Join(jailTmpDir, filepath.Base(hostSocketPath))
	
	// Create empty file for bind mount target
	if err := os.WriteFile(jailSocketPath, []byte{}, 0644); err != nil {
		return fmt.Errorf("failed to create bind mount target: %w", err)
	}
	
	// Bind mount the socket from host to jail
	if err := syscall.Mount(hostSocketPath, jailSocketPath, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("failed to bind mount UFFD socket: %w", err)
	}
	
	zap.L().Info("successfully bind mounted UFFD socket into jail",
		zap.String("host_path", hostSocketPath),
		zap.String("jail_path", jailSocketPath),
		zap.String("sandbox_id", p.files.SandboxID))
	
	return nil
}

// Pid returns the PID of the jailer process
func (p *Process) Pid() (int, error) {
	if p.cmd == nil || p.cmd.Process == nil {
		return 0, fmt.Errorf("fc process not started")
	}
	return p.cmd.Process.Pid, nil
}

// Stop stops the Firecracker process
func (p *Process) Stop() error {
	if p.cmd == nil || p.cmd.Process == nil {
		return fmt.Errorf("fc process not started")
	}

	// Without --daemonize, just signal the jailer process directly
	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Signal(syscall.SIGTERM)
		time.Sleep(2 * time.Second)
	}

	// Without --daemonize, work with the jailer process directly
	jailerPid := p.cmd.Process.Pid
	
	// Check jailer process state  
	state, err := getProcessState(jailerPid)
	if err != nil {
		zap.L().Warn("failed to get jailer process state", zap.Error(err), logger.WithSandboxID(p.files.SandboxID))
	} else if strings.TrimSpace(state) == "D" {
		zap.L().Info("jailer process is in the D state before we call SIGTERM", logger.WithSandboxID(p.files.SandboxID))
	}

	// Wait for graceful shutdown of jailer process (without daemonize, jailer stays running)
	if p.cmd != nil && p.cmd.Process != nil {
		// Monitor the jailer process directly
		done := make(chan struct{})
		go func() {
			for {
				// Check if jailer process still exists by sending signal 0
				if err := p.cmd.Process.Signal(syscall.Signal(0)); err != nil {
					close(done)
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()

		select {
		case <-done:
			// Jailer process exited gracefully
		case <-time.After(10 * time.Second):
			// Check process state after timeout
			state, err := getProcessState(jailerPid)
			if err != nil {
				zap.L().Warn("failed to get jailer process state after timeout", zap.Error(err), logger.WithSandboxID(p.files.SandboxID))
			} else if strings.TrimSpace(state) == "D" {
				zap.L().Info("jailer process is in the D state after timeout", logger.WithSandboxID(p.files.SandboxID))
			}
			
			// Force kill jailer
			if p.cmd != nil && p.cmd.Process != nil {
				p.cmd.Process.Kill()
			}
			<-done
			zap.L().Info("sent SIGKILL to jailer process because it was not responding to SIGTERM for 10 seconds", logger.WithSandboxID(p.files.SandboxID))
		}
	}

	// Cleanup socket symlink
	if _, err := os.Lstat(p.firecrackerSocketPath); err == nil {
		os.Remove(p.firecrackerSocketPath)
	}

	// Cleanup bind mounts before removing jail directory
	jailKernel := filepath.Join(p.jailRoot, "kernel")
	if _, err := os.Stat(jailKernel); err == nil {
		// Try to unmount kernel bind mount (ignore errors if not mounted)
		syscall.Unmount(jailKernel, 0)
	}
	
	// Cleanup rootfs bind mount
	jailBuildRootfsPath := filepath.Join(p.jailRoot, strings.TrimPrefix(p.buildRootfsPath, "/"))
	if _, err := os.Stat(jailBuildRootfsPath); err == nil {
		// Try to unmount rootfs bind mount (ignore errors if not mounted)
		syscall.Unmount(jailBuildRootfsPath, 0)
	}
	
	// Cleanup snapshot bind mounts
	snapfilePath := filepath.Join(p.jailRoot, fmt.Sprintf("snapfile-%s", p.files.SandboxID))
	if _, err := os.Stat(snapfilePath); err == nil {
		// Try to unmount snapshot bind mount (ignore errors if not mounted)
		syscall.Unmount(snapfilePath, 0)
	}
	
	memfilePath := filepath.Join(p.jailRoot, fmt.Sprintf("memfile-%s", p.files.SandboxID))
	if _, err := os.Stat(memfilePath); err == nil {
		// Try to unmount memfile bind mount (ignore errors if not mounted)
		syscall.Unmount(memfilePath, 0)
	}
	
	// Cleanup jail directory
	jailPath := filepath.Dir(p.jailRoot)
	os.RemoveAll(jailPath)

	return nil
}

// Pause pauses the VM
func (p *Process) Pause(ctx context.Context, tracer trace.Tracer) error {
	ctx, childSpan := tracer.Start(ctx, "pause-fc")
	defer childSpan.End()
	return p.client.pauseVM(ctx)
}

// CreateSnapshot creates a VM snapshot
func (p *Process) CreateSnapshot(ctx context.Context, tracer trace.Tracer, snapfilePath string, memfilePath string) error {
	ctx, childSpan := tracer.Start(ctx, "create-snapshot-fc")
	defer childSpan.End()
	
	// For jailer implementation, we bind mount host snapshot files into jail
	// This allows Firecracker to write directly to the original host paths with zero copying
	jailSnapfilePath, err := p.bindMountHostFileIntoJail(snapfilePath, "snapfile")
	if err != nil {
		return fmt.Errorf("failed to bind mount snapfile: %w", err)
	}
	
	jailMemfilePath, err := p.bindMountHostFileIntoJail(memfilePath, "memfile") 
	if err != nil {
		return fmt.Errorf("failed to bind mount memfile: %w", err)
	}
	
	zap.L().Info("snapshot paths configured for jailer with zero-copy bind mounts",
		zap.String("host_snapfile", snapfilePath),
		zap.String("jail_snapfile", jailSnapfilePath),
		zap.String("host_memfile", memfilePath),
		zap.String("jail_memfile", jailMemfilePath))
	
	// Create snapshot using jail paths - Firecracker writes directly to original host files
	return p.client.createSnapshot(ctx, jailSnapfilePath, jailMemfilePath)
}

// getProcessState helper function from original
func getProcessState(pid int) (string, error) {
	cmd, err := exec.Command("ps", "-o", "stat=", "-p", fmt.Sprint(pid)).Output()
	if err != nil {
		return "", err
	}
	return string(cmd), nil
}

// enterNetworkNamespace switches the current process to E2B's network namespace
// This allows Firecracker to access TAP devices created in the namespace
func (p *Process) enterNetworkNamespace() error {
	// Get the namespace path for this slot
	namespacePath := filepath.Join("/var/run/netns", p.slot.NamespaceID())
	
	zap.L().Info("checking network namespace existence", zap.String("namespace_path", namespacePath))
	
	// Check if the namespace exists
	if _, err := os.Stat(namespacePath); err != nil {
		return fmt.Errorf("network namespace %s does not exist: %w", namespacePath, err)
	}
	
	zap.L().Info("network namespace exists, getting handle")
	
	// Get the namespace
	netns, err := ns.GetNS(namespacePath)
	if err != nil {
		return fmt.Errorf("failed to get network namespace %s: %w", namespacePath, err)
	}
	defer netns.Close()
	
	zap.L().Info("setting network namespace for current process")
	
	// Set the namespace for this process
	// This is permanent - the process will remain in this namespace
	if err := netns.Set(); err != nil {
		return fmt.Errorf("failed to enter network namespace %s: %w", namespacePath, err)
	}
	
	zap.L().Info("successfully switched to network namespace", zap.String("namespace_path", namespacePath))
	return nil
}

// createTapInNetns creates a TAP interface in the target network namespace with proper ownership
// This allows Firecracker to attach to the TAP without needing CAP_NET_ADMIN capability
func (p *Process) createTapInNetns() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get current namespace to restore later
	currentNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get current network namespace: %w", err)
	}
	defer currentNS.Close()

	// Get target namespace path
	namespacePath := filepath.Join("/var/run/netns", p.slot.NamespaceID())
	targetNS, err := netns.GetFromPath(namespacePath)
	if err != nil {
		return fmt.Errorf("failed to get target network namespace %s: %w", namespacePath, err)
	}
	defer targetNS.Close()

	// Switch to target namespace
	if err := netns.Set(targetNS); err != nil {
		return fmt.Errorf("failed to switch to target namespace: %w", err)
	}
	
	// Ensure we restore the original namespace
	defer func() {
		if err := netns.Set(currentNS); err != nil {
			zap.L().Error("failed to restore original network namespace", zap.Error(err))
		}
	}()

	tapName := p.slot.TapName()
	
	zap.L().Info("creating TAP interface in network namespace",
		zap.String("namespace_path", namespacePath),
		zap.String("tap_name", tapName),
		zap.String("sandbox_id", p.files.SandboxID))

	// Check if TAP interface already exists and delete it
	if existingLink, err := netlink.LinkByName(tapName); err == nil {
		zap.L().Info("TAP interface already exists, deleting it first",
			zap.String("tap_name", tapName))
		if err := netlink.LinkDel(existingLink); err != nil {
			zap.L().Warn("failed to delete existing TAP interface", 
				zap.String("tap_name", tapName), zap.Error(err))
		}
	}

	// Create TAP interface with proper ownership (basic configuration)
	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: tapName},
		Mode:      netlink.TUNTAP_MODE_TAP,
		Flags:     0, // Use basic TAP configuration for compatibility
		Owner:     1000, // Jailer uid
		Group:     1000, // Jailer gid
	}

	if err := netlink.LinkAdd(tap); err != nil {
		return fmt.Errorf("failed to create TAP interface %s: %w", tapName, err)
	}

	// Set MTU to 1500 (standard Ethernet MTU)
	if err := netlink.LinkSetMTU(tap, 1500); err != nil {
		return fmt.Errorf("failed to set TAP MTU: %w", err)
	}

	// CRITICAL FIX: Assign IP address to TAP device - this was missing!
	// The TAP device needs to have the proper IP address configured for routing
	tapIP := p.slot.TapIPString() + "/" + strconv.Itoa(p.slot.TapMask())
	
	zap.L().Info("assigning IP address to TAP device", 
		zap.String("tap_name", tapName),
		zap.String("tap_ip_cidr", tapIP))
	
	tapAddr, err := netlink.ParseAddr(tapIP)
	if err != nil {
		return fmt.Errorf("failed to parse TAP IP address %s: %w", tapIP, err)
	}
	
	if err := netlink.AddrAdd(tap, tapAddr); err != nil {
		return fmt.Errorf("failed to assign IP %s to TAP interface %s: %w", tapIP, tapName, err)
	}

	// Bring the interface up
	if err := netlink.LinkSetUp(tap); err != nil {
		return fmt.Errorf("failed to bring TAP interface up: %w", err)
	}

	// CRITICAL FIX: Disable reverse path filtering for TAP device to prevent martian source errors
	// This allows packets from VM (169.254.0.21) to arrive on TAP interface without being rejected
	if err := p.disableReversePathFiltering(tapName); err != nil {
		zap.L().Warn("failed to disable reverse path filtering for TAP device", 
			zap.String("tap_name", tapName), zap.Error(err))
		// Continue anyway - this is a compatibility fix, not critical for basic function
	}

	zap.L().Info("successfully created TAP interface with proper ownership and network config",
		zap.String("tap_name", tapName),
		zap.Uint32("owner", 1000),
		zap.Uint32("group", 1000),
		zap.String("sandbox_id", p.files.SandboxID))

	return nil
}

// disableReversePathFiltering disables reverse path filtering for the specified interface
// This prevents martian source errors when VM packets don't match interface routing expectations
func (p *Process) disableReversePathFiltering(interfaceName string) error {
	// Disable reverse path filtering for specific interface
	cmd := exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", interfaceName))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to disable rp_filter for %s: %w", interfaceName, err)
	}

	zap.L().Info("disabled reverse path filtering for interface to prevent martian source errors",
		zap.String("interface", interfaceName))

	return nil
}

// setupNetworkAndStartJailer creates TAP device in target namespace and starts jailer
// OPTION B: Jailer runs within E2B's pre-configured network namespace
func (p *Process) setupNetworkAndStartJailer(ctx context.Context, stdoutExternal, stderrExternal io.Writer) (*bytes.Buffer, error) {
	var stderrBuf bytes.Buffer
	
	// Create TAP device in the target network namespace first
	err := p.createTapInNetns()
	if err != nil {
		return &stderrBuf, fmt.Errorf("failed to create TAP device in network namespace: %w", err)
	}
	
	// Verify network namespace exists before starting jailer
	namespacePath := filepath.Join("/var/run/netns", p.slot.NamespaceID())
	if _, err := os.Stat(namespacePath); err != nil {
		return &stderrBuf, fmt.Errorf("network namespace does not exist: %s", namespacePath)
	}
	
	zap.L().Info("switching to E2B network namespace to start jailer", 
		zap.String("namespace_path", namespacePath),
		zap.String("namespace_id", p.slot.NamespaceID()))

	// OPTION B: Switch to E2B's network namespace, then start jailer
	// Jailer will inherit the network namespace and run securely within it
	err = ns.WithNetNSPath(namespacePath, func(_ ns.NetNS) error {
		zap.L().Info("now running within E2B's network namespace, starting jailer")
		
		// Build jailer command (without --netns flag)
		// Default to non-provision phase (false) for legacy compatibility
		p.cmd = p.buildJailerCommand(false)
		
		// Log the exact command being executed
		zap.L().Info("starting jailer within E2B namespace", 
			zap.String("command", p.cmd.Path),
			zap.Strings("args", p.cmd.Args),
			zap.String("jail_root", p.jailRoot))
		
		// Setup stderr capture for debugging
		if stderrExternal != nil {
			p.cmd.Stderr = io.MultiWriter(&stderrBuf, stderrExternal)
		} else {
			p.cmd.Stderr = &stderrBuf
		}
		
		if stdoutExternal != nil {
			p.cmd.Stdout = stdoutExternal
		}
		
		// Console output is already being captured in buildJailerCommand()
		
		// Start jailer process - inherits current network namespace (E2B's)
		if err := p.cmd.Start(); err != nil {
			return fmt.Errorf("failed to start jailer within namespace: %w", err)
		}
		
		zap.L().Info("jailer started successfully within E2B's network namespace",
			zap.Int("jailer_pid", p.cmd.Process.Pid))
		
		return nil
	})
	
	if err != nil {
		return &stderrBuf, fmt.Errorf("failed to start jailer in network namespace: %w", err)
	}
	
	return &stderrBuf, nil
}
