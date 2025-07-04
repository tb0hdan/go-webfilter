package proc

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
	"github.com/tb0hdan/go-webfilter/pkg/utils"
)

type ProcessInfo struct {
	PID     string
	Binary  string
	Cmdline string
	// Additional fields can be added as needed
	UID     string // UID of the process owner
	SrcAddr string
	SrcPort string // Source port of the process
	DstAddr string
	DstPort string // Destination port of the process
	DstHost string
}

type ProcLister struct {
	logger zerolog.Logger
}

func (pl *ProcLister) GetPIDs() ([]string, error) {
	// Read the /proc directory to get the list of inodes
	reg := regexp.MustCompile("^[0-9]+$")
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc directory: %v", err)
	}

	var pids []string
	for _, dir := range dirs {
		if reg.MatchString(dir.Name()) {
			pids = append(pids, dir.Name())
		}
	}

	return pids, nil
}

func (pl *ProcLister) GetProcFDs(pid string) ([]string, error) {
	// Read the /proc/[pid]/fd directory to get the list of file descriptors
	fdsDir := fmt.Sprintf("/proc/%s/fd", pid)
	dirs, err := os.ReadDir(fdsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s directory: %v", fdsDir, err)
	}

	var fds []string
	for _, dir := range dirs {
		fds = append(fds, dir.Name())
	}

	return fds, nil
}

func (pl *ProcLister) ReadProcFD(pid, fd string) (string, error) {
	// Read the symbolic link of the file descriptor
	fdPath := fmt.Sprintf("/proc/%s/fd/%s", pid, fd)
	target, err := os.Readlink(fdPath)
	if err != nil {
		return "", fmt.Errorf("failed to read link %s: %v", fdPath, err)
	}
	return strings.TrimSpace(target), nil
}

func (pl *ProcLister) GetPidSocketInodes(pid string) ([]string, error) {
	// Get the file descriptors for the given PID
	fds, err := pl.GetProcFDs(pid)
	if err != nil {
		return nil, err
	}

	var sockets []string
	for _, fd := range fds {
		target, err := pl.ReadProcFD(pid, fd)
		if err != nil {
			continue // Skip if we can't read the FD
		}
		if strings.HasPrefix(target, "socket:") {
			sockets = append(sockets, strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"))
		}
	}

	return sockets, nil
}

func (pl *ProcLister) GetProcessInfoByInode(inode string) (*ProcessInfo, error) {
	// Read the /proc directory to get the list of PIDs
	pids, err := pl.GetPIDs()
	if err != nil {
		return nil, fmt.Errorf("failed to get PIDs: %v", err)
	}

	for _, pid := range pids {
		sockets, err := pl.GetPidSocketInodes(pid)
		if err != nil {
			continue // Skip if we can't get sockets for this PID
		}
		if utils.Index(sockets, func(s string) bool { return s == inode }) != -1 {
			// If the inode is found in the sockets, read the cmdline
			cmdlinePath := fmt.Sprintf("/proc/%s/cmdline", pid)
			cmdlineData, err := os.ReadFile(cmdlinePath)
			if err != nil {
				return nil, fmt.Errorf("failed to read cmdline for PID %s: %v", pid, err)
			}
			// Read the binary name from the exe link
			exePath := fmt.Sprintf("/proc/%s/exe", pid)
			binary, err := os.Readlink(exePath)
			if err != nil {
				return nil, fmt.Errorf("failed to read exe link for PID %s: %v", pid, err)
			}
			return &ProcessInfo{
				Binary:  strings.TrimSpace(binary),
				Cmdline: strings.TrimSpace(string(cmdlineData)),
				PID:     pid,
			}, nil
		}
	}

	return nil, fmt.Errorf("inode %s not found in any process", inode)
}

func New(logger zerolog.Logger) *ProcLister {
	return &ProcLister{
		logger: logger,
	}
}
