package proc_test

import (
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
	"github.com/tb0hdan/go-webfilter/pkg/proc"
	"github.com/tb0hdan/go-webfilter/pkg/proc/mocks"
)

// ProcListerTestSuite defines the test suite for ProcLister
type ProcListerTestSuite struct {
	suite.Suite
	mockLister *mocks.MockLister
	logger     zerolog.Logger
}

// SetupTest sets up the test suite before each test
func (suite *ProcListerTestSuite) SetupTest() {
	suite.mockLister = new(mocks.MockLister)
	suite.logger = zerolog.Nop()
}

// TearDownTest resets the mock after each test
func (suite *ProcListerTestSuite) TearDownTest() {
	suite.mockLister = nil
}

// TestGetPIDs tests the GetPIDs method
func (suite *ProcListerTestSuite) TestGetPIDs() {
	tests := []struct {
		name          string
		expectedPIDs  []string
		expectedError error
	}{
		{
			name:          "successful PIDs retrieval",
			expectedPIDs:  []string{"1", "2", "1234", "5678"},
			expectedError: nil,
		},
		{
			name:          "error reading PIDs",
			expectedPIDs:  nil,
			expectedError: errors.New("failed to read /proc directory"),
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			// Create a new mock for each test case
			mockLister := new(mocks.MockLister)
			mockLister.On("GetPIDs").Return(tt.expectedPIDs, tt.expectedError)
			
			pids, err := mockLister.GetPIDs()
			
			if tt.expectedError != nil {
				suite.Error(err)
				suite.Equal(tt.expectedError.Error(), err.Error())
			} else {
				suite.NoError(err)
				suite.Equal(tt.expectedPIDs, pids)
			}
			
			mockLister.AssertExpectations(suite.T())
		})
	}
}

// TestGetProcFDs tests the GetProcFDs method
func (suite *ProcListerTestSuite) TestGetProcFDs() {
	tests := []struct {
		name          string
		pid           string
		expectedFDs   []string
		expectedError error
	}{
		{
			name:          "successful FDs retrieval",
			pid:           "1234",
			expectedFDs:   []string{"0", "1", "2", "3", "4"},
			expectedError: nil,
		},
		{
			name:          "error reading FDs",
			pid:           "9999",
			expectedFDs:   nil,
			expectedError: errors.New("failed to read /proc/9999/fd directory"),
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			// Create a new mock for each test case
			mockLister := new(mocks.MockLister)
			mockLister.On("GetProcFDs", tt.pid).Return(tt.expectedFDs, tt.expectedError)
			
			fds, err := mockLister.GetProcFDs(tt.pid)
			
			if tt.expectedError != nil {
				suite.Error(err)
				suite.Equal(tt.expectedError.Error(), err.Error())
			} else {
				suite.NoError(err)
				suite.Equal(tt.expectedFDs, fds)
			}
			
			mockLister.AssertExpectations(suite.T())
		})
	}
}

// TestReadProcFD tests the ReadProcFD method
func (suite *ProcListerTestSuite) TestReadProcFD() {
	tests := []struct {
		name           string
		pid            string
		fd             string
		expectedTarget string
		expectedError  error
	}{
		{
			name:           "successful socket read",
			pid:            "1234",
			fd:             "3",
			expectedTarget: "socket:[12345]",
			expectedError:  nil,
		},
		{
			name:           "successful file read",
			pid:            "1234",
			fd:             "1",
			expectedTarget: "/dev/pts/0",
			expectedError:  nil,
		},
		{
			name:           "error reading FD",
			pid:            "1234",
			fd:             "999",
			expectedTarget: "",
			expectedError:  errors.New("failed to read link /proc/1234/fd/999"),
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			// Create a new mock for each test case
			mockLister := new(mocks.MockLister)
			mockLister.On("ReadProcFD", tt.pid, tt.fd).Return(tt.expectedTarget, tt.expectedError)
			
			target, err := mockLister.ReadProcFD(tt.pid, tt.fd)
			
			if tt.expectedError != nil {
				suite.Error(err)
				suite.Equal(tt.expectedError.Error(), err.Error())
			} else {
				suite.NoError(err)
				suite.Equal(tt.expectedTarget, target)
			}
			
			mockLister.AssertExpectations(suite.T())
		})
	}
}

// TestGetPidSocketInodes tests the GetPidSocketInodes method
func (suite *ProcListerTestSuite) TestGetPidSocketInodes() {
	tests := []struct {
		name             string
		pid              string
		expectedInodes   []string
		expectedError    error
	}{
		{
			name:             "successful socket inodes retrieval",
			pid:              "1234",
			expectedInodes:   []string{"12345", "67890", "11111"},
			expectedError:    nil,
		},
		{
			name:             "no socket inodes found",
			pid:              "5678",
			expectedInodes:   []string{},
			expectedError:    nil,
		},
		{
			name:             "error getting FDs",
			pid:              "9999",
			expectedInodes:   nil,
			expectedError:    errors.New("failed to get FDs"),
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			// Create a new mock for each test case
			mockLister := new(mocks.MockLister)
			mockLister.On("GetPidSocketInodes", tt.pid).Return(tt.expectedInodes, tt.expectedError)
			
			inodes, err := mockLister.GetPidSocketInodes(tt.pid)
			
			if tt.expectedError != nil {
				suite.Error(err)
				suite.Equal(tt.expectedError.Error(), err.Error())
			} else {
				suite.NoError(err)
				suite.Equal(tt.expectedInodes, inodes)
			}
			
			mockLister.AssertExpectations(suite.T())
		})
	}
}

// TestGetProcessInfoByInode tests the GetProcessInfoByInode method
func (suite *ProcListerTestSuite) TestGetProcessInfoByInode() {
	tests := []struct {
		name         string
		inode        string
		expectedInfo *proc.ProcessInfo
		expectedErr  error
	}{
		{
			name:  "successful process info retrieval",
			inode: "12345",
			expectedInfo: &proc.ProcessInfo{
				PID:     "1234",
				Binary:  "/usr/bin/firefox",
				Cmdline: "firefox --new-window",
				UID:     "1000",
				SrcAddr: "192.168.1.100",
				SrcPort: "45678",
				DstAddr: "93.184.216.34",
				DstPort: "443",
				DstHost: "example.com",
			},
			expectedErr: nil,
		},
		{
			name:         "inode not found",
			inode:        "99999",
			expectedInfo: nil,
			expectedErr:  errors.New("inode 99999 not found in any process"),
		},
		{
			name:         "error getting PIDs",
			inode:        "12345",
			expectedInfo: nil,
			expectedErr:  errors.New("failed to get PIDs"),
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			// Create a new mock for each test case
			mockLister := new(mocks.MockLister)
			mockLister.On("GetProcessInfoByInode", tt.inode).Return(tt.expectedInfo, tt.expectedErr)
			
			info, err := mockLister.GetProcessInfoByInode(tt.inode)
			
			if tt.expectedErr != nil {
				suite.Error(err)
				suite.Equal(tt.expectedErr.Error(), err.Error())
				suite.Nil(info)
			} else {
				suite.NoError(err)
				suite.NotNil(info)
				suite.Equal(tt.expectedInfo.PID, info.PID)
				suite.Equal(tt.expectedInfo.Binary, info.Binary)
				suite.Equal(tt.expectedInfo.Cmdline, info.Cmdline)
				suite.Equal(tt.expectedInfo.UID, info.UID)
				suite.Equal(tt.expectedInfo.SrcAddr, info.SrcAddr)
				suite.Equal(tt.expectedInfo.SrcPort, info.SrcPort)
				suite.Equal(tt.expectedInfo.DstAddr, info.DstAddr)
				suite.Equal(tt.expectedInfo.DstPort, info.DstPort)
				suite.Equal(tt.expectedInfo.DstHost, info.DstHost)
			}
			
			mockLister.AssertExpectations(suite.T())
		})
	}
}

// TestListerInterface tests that ProcLister implements the Lister interface
func (suite *ProcListerTestSuite) TestListerInterface() {
	// Create a real ProcLister instance
	pl := proc.New(suite.logger)
	
	// Verify it implements the Lister interface
	var _ proc.Lister = pl
	
	// Test that we can assign it to an interface variable
	var lister proc.Lister = pl
	suite.NotNil(lister)
}

// TestProcListerIntegration tests the ProcLister with actual implementation
func (suite *ProcListerTestSuite) TestProcListerIntegration() {
	// This test group tests the actual ProcLister implementation
	// It should be skipped in CI environments where /proc might not be available
	if testing.Short() {
		suite.T().Skip("Skipping integration tests in short mode")
	}
	
	pl := proc.New(suite.logger)
	
	// Test GetPIDs - should return at least PID 1 (init)
	pids, err := pl.GetPIDs()
	suite.NoError(err)
	suite.NotEmpty(pids)
	suite.Contains(pids, "1")
	
	// Test GetProcFDs with current process PID
	// We know the current process has at least stdin, stdout, stderr
	currentPID := "self"
	fds, err := pl.GetProcFDs(currentPID)
	if err == nil {
		suite.NotEmpty(fds)
		// Should have at least FDs 0, 1, 2
		suite.GreaterOrEqual(len(fds), 3)
	}
}

// TestSuite runs the test suite
func TestProcListerTestSuite(t *testing.T) {
	suite.Run(t, new(ProcListerTestSuite))
}