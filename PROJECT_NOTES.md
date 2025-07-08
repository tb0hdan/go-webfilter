# Go-WebFilter Project Notes

## Overview
**go-webfilter** is a pluggable, intercepting web filter written in Go that acts as a transparent HTTP/HTTPS proxy. It intercepts HTTP traffic from local processes, analyzes the requests, and provides detailed information about which processes are making network connections. The application now supports both HTTP and HTTPS protocols with self-signed certificates for secure connections.

## Architecture

### Core Components

#### 1. Main Entry Point (`cmd/webfilter/main.go`)
- **Purpose**: Application entry point with CLI argument parsing
- **Key Features**:
  - Command-line flags for debug mode and request/response dumping
  - Graceful shutdown handling with signal context
  - Dual server setup: HTTP and HTTPS with self-signed certificates
  - Echo web server setup and lifecycle management for both servers
  - Zerolog structured logging configuration

#### 2. HTTP/HTTPS Server (`pkg/server/server.go`)
- **Purpose**: Core HTTP/HTTPS proxy server that intercepts and processes web requests
- **Key Features**:
  - **Dual Protocol Support**: Runs both HTTP and HTTPS servers on separate dynamically allocated ports
  - **Traffic Interception**: Intercepts HTTP requests and forwards them to original destinations
  - **Process Identification**: Identifies which local process initiated each request by:
    - Parsing `/proc/net/tcp` to find connection details
    - Matching connection source/destination with request metadata
    - Extracting process information via inode lookup
  - **Request/Response Handling**: Supports all HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD)
  - **Optional Dumping**: Can dump full HTTP requests/responses for debugging

#### 3. Firewall Management (`pkg/firewall/`)
- **Interface** (`firewall.go`): Defines firewall operations interface
- **NFTables Implementation** (`nft/nft.go`):
  - **Traffic Redirection**: Creates nftables rules to redirect HTTP traffic (port 80) to the proxy
  - **Rule Management**: Automatically installs and cleans up firewall rules
  - **Root Exclusion**: Excludes traffic from root user (uid 0) to prevent infinite loops
  - **Netfilter Hook**: Uses OUTPUT chain with DSTNAT priority (-100)

#### 4. Process Analysis (`pkg/proc/`)
- **Interface** (`interfaces.go`): Defines the `Lister` interface for process operations
- **Implementation** (`proc_lister.go`): Concrete implementation of the `Lister` interface
- **Purpose**: Identifies processes by analyzing `/proc` filesystem
- **Key Features**:
  - **Process Discovery**: Scans `/proc` for active PIDs
  - **Socket Tracking**: Maps socket inodes to file descriptors
  - **Process Metadata**: Extracts binary path, command line, and PID
  - **Connection Mapping**: Links network connections to specific processes
  - **Interface-Based Design**: Uses dependency injection for testability
- **Testing** (`proc_lister_test.go`): Comprehensive test suite with mocking
- **Mocks** (`mocks/lister.go`): Mock implementation for testing

#### 5. Utilities (`pkg/utils/`)
- **General Utils** (`utils.go`):
  - Generic slice index function with type parameters
  - Hex address decoding for `/proc/net/tcp` format (little-endian conversion)
  - Network address parsing utilities for IP:port combinations
- **Port Utils** (`port.go`):
  - Dynamic port allocation for proxy servers using system-assigned free ports
- **Certificate Utils** (`cert.go`):
  - Self-signed certificate generation for HTTPS server
  - RSA 2048-bit key generation with proper certificate properties
  - Certificate valid for 1 year with localhost/127.0.0.1 SANs
  - Persistent certificate storage in build directory
  - Support for both custom and snake oil certificate modes
- **Testing** (`utils_test.go`): Comprehensive test suite with 83.6% coverage
  - Unit tests for all utility functions with success/failure scenarios
  - Table-driven tests for hex decoding and address parsing
  - Benchmark tests for performance measurement
  - Certificate generation and validation testing
  - Cross-platform temporary directory handling

## Technical Implementation

### Traffic Interception Flow
1. **NFTables Rules**: Redirect HTTP traffic (port 80) to proxy server
2. **Proxy Reception**: Server receives redirected traffic on dynamic port
3. **Process Identification**: Analyze connection metadata to identify source process
4. **Request Forwarding**: Forward original request to intended destination
5. **Response Relay**: Return response to original client

### Process Identification Algorithm
1. Extract client address from HTTP request
2. Parse `/proc/net/tcp` for matching connection
3. Find socket inode from connection entry
4. Scan process file descriptors (`/proc/[pid]/fd/`) for matching inode
5. Extract process information (binary, cmdline, PID)

### Network Address Parsing
- Handles hexadecimal-encoded addresses from `/proc/net/tcp`
- Converts little-endian hex format to standard IP:port notation
- Supports both IPv4 addresses and port numbers

## Security Considerations

### Firewall Rules
- Uses nftables for transparent traffic redirection
- Applies only to HTTP traffic (port 80)
- Excludes root user traffic to prevent interference
- Automatically cleans up rules on shutdown

### Process Analysis
- Read-only access to `/proc` filesystem
- No modification of process state or memory
- Minimal system impact through efficient parsing

### Network Interception
- Transparent proxy mode (no client configuration required)
- Preserves original request headers and body
- Maintains HTTP semantics and status codes
- HTTPS server with self-signed certificates for secure connections

## Dependencies

### Go Modules
- **Echo v4**: High-performance HTTP web framework
- **Zerolog**: Structured logging library
- **Testify**: Testing toolkit with assertions and mocking
- **Lecho**: Zerolog integration for Echo framework
- **Standard Library**: Network, OS, and system utilities

### System Requirements
- **Linux**: Uses `/proc` filesystem and nftables
- **Root Privileges**: Required for nftables rule modification
- **nftables**: Modern Linux netfilter framework

## Usage Patterns

### Development/Debug Mode
```bash
sudo go run cmd/webfilter/main.go --debug --dump
```
- Enables debug logging
- Dumps full HTTP requests and responses
- Provides detailed process identification info
- Logs HTTP and HTTPS server ports on startup

### Production Mode
```bash
sudo go run cmd/webfilter/main.go
```
- Standard operation with info-level logging
- Minimal output for production environments
- Both HTTP and HTTPS servers start automatically on dynamically allocated ports

## File Structure Analysis

```
go-webfilter/
├── cmd/webfilter/main.go          # Application entry point
├── pkg/
│   ├── firewall/
│   │   ├── firewall.go            # Firewall interface
│   │   └── nft/nft.go            # NFTables implementation
│   ├── proc/
│   │   ├── interfaces.go          # Process lister interface definition
│   │   ├── proc_lister.go         # Process identification implementation
│   │   ├── proc_lister_test.go    # Comprehensive test suite
│   │   └── mocks/
│   │       └── lister.go          # Mock implementation for testing
│   ├── server/server.go           # HTTP/HTTPS proxy server
│   └── utils/
│       ├── cert.go               # Certificate generation utilities
│       ├── port.go               # Port allocation utilities
│       ├── utils.go              # Address parsing utilities
│       └── utils_test.go         # Comprehensive test suite
├── build/                         # Build artifacts and certificates
├── Makefile                       # Build, test, and lint commands
├── .golangci.yml                  # Linter configuration
├── go.mod                        # Go module definition
├── go.sum                        # Dependency checksums
├── CLAUDE.md                      # Claude assistant instructions
├── PROJECT_NOTES.md               # This file - project documentation
└── README.md                     # Basic usage instructions
```

## Key Design Decisions

1. **Transparent Proxy**: Uses nftables redirection instead of explicit proxy configuration
2. **Process Attribution**: Links network requests to specific processes for monitoring
3. **Non-Intrusive**: Read-only analysis without modifying process behavior
4. **Pluggable Architecture**: Interface-based design for firewall implementations
5. **Graceful Lifecycle**: Proper setup/teardown of system resources
6. **Testability**: Interface-based design with dependency injection for comprehensive testing
7. **Certificate Management**: Persistent certificate storage in build directory

## Operational Notes

- Requires root privileges for nftables rule management
- Automatically allocates free ports to avoid conflicts
- Handles process cleanup on shutdown signals
- Supports concurrent request processing
- Maintains HTTP compliance for transparent operation

## Recent Updates

### Utils Package Testing Infrastructure (Latest)
- Created comprehensive test suite `pkg/utils/utils_test.go` with 83.6% coverage
- Added unit tests for all utility functions: Index, DecodeHex, ParseHexAddr, GetFreePort
- Implemented certificate testing with LoadOrGenerateCert and generateAndSaveCert validation
- Added table-driven tests for comprehensive input validation and edge cases
- Included benchmark tests for performance measurement of core utility functions
- Cross-platform temporary directory handling for certificate generation tests
- Snake oil certificate mode testing with proper error handling
- Proper test isolation using temporary working directories

### Process Testing Infrastructure
- Added comprehensive interface-based architecture with `pkg/proc/interfaces.go`
- Implemented mock-based testing with `pkg/proc/mocks/lister.go`
- Created extensive test suite `pkg/proc/proc_lister_test.go` with unit and integration tests
- Added golangci-lint configuration for code quality enforcement
- Updated certificate utilities with proper error handling for linter compliance
- Implemented persistent certificate storage in build directory

### HTTPS Server Implementation
- Added self-signed certificate generation utility in `pkg/utils/cert.go`
- Modified server structure to support dual-port operation (HTTP and HTTPS)
- Updated main.go to launch both HTTP and HTTPS servers concurrently
- Both servers share the same route handlers and process identification logic
- HTTPS server uses TLS with dynamically generated self-signed certificates
- Certificate persistence prevents regeneration on each startup

## Testing & Quality Assurance

### Test Suite Features
- **Unit Tests**: Mock-based testing for all interface methods and utility functions
- **Integration Tests**: Real `/proc` filesystem testing (skippable in CI)
- **Coverage Reports**: HTML coverage reports generated in build directory
- **Interface Compliance**: Verification that implementations satisfy interfaces
- **Error Handling**: Comprehensive error scenario testing
- **Utils Testing**: 83.6% coverage with table-driven tests and benchmarks
- **Certificate Testing**: Full certificate generation and validation workflows
- **Cross-Platform**: Temporary directory handling for portability

### Code Quality
- **Linter Integration**: golangci-lint with comprehensive rule set
- **Make Targets**: Automated build, test, and lint workflow
- **Error Handling**: Proper error checking and resource cleanup
- **Documentation**: Extensive inline documentation and comments

## Future Enhancement Possibilities

- Additional firewall backend implementations (iptables, etc.)
- Process filtering and policy enforcement
- Request/response modification capabilities
- Performance metrics and monitoring
- Configuration file support for complex setups
- Support for custom certificate configuration
- Continuous integration pipeline setup
- Performance benchmarking and optimization