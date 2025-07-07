package proc

// Lister defines the interface for process listing operations
type Lister interface {
	// GetPIDs returns a list of all process IDs in the system
	GetPIDs() ([]string, error)
	
	// GetProcFDs returns a list of file descriptors for a given process ID
	GetProcFDs(pid string) ([]string, error)
	
	// ReadProcFD reads the symbolic link of a file descriptor
	ReadProcFD(pid, fd string) (string, error)
	
	// GetPidSocketInodes returns a list of socket inodes for a given process ID
	GetPidSocketInodes(pid string) ([]string, error)
	
	// GetProcessInfoByInode returns process information for a given socket inode
	GetProcessInfoByInode(inode string) (*ProcessInfo, error)
}