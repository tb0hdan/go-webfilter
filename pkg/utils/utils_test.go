package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndex(t *testing.T) {
	t.Run("find existing element", func(t *testing.T) {
		arr := []int{1, 2, 3, 4, 5}
		index := Index(arr, func(x int) bool { return x == 3 })
		assert.Equal(t, 2, index)
	})

	t.Run("element not found", func(t *testing.T) {
		arr := []int{1, 2, 3, 4, 5}
		index := Index(arr, func(x int) bool { return x == 6 })
		assert.Equal(t, -1, index)
	})

	t.Run("empty array", func(t *testing.T) {
		arr := []int{}
		index := Index(arr, func(x int) bool { return x == 1 })
		assert.Equal(t, -1, index)
	})

	t.Run("string slice", func(t *testing.T) {
		arr := []string{"apple", "banana", "cherry"}
		index := Index(arr, func(s string) bool { return s == "banana" })
		assert.Equal(t, 1, index)
	})

	t.Run("first element", func(t *testing.T) {
		arr := []int{10, 20, 30}
		index := Index(arr, func(x int) bool { return x == 10 })
		assert.Equal(t, 0, index)
	})

	t.Run("last element", func(t *testing.T) {
		arr := []int{10, 20, 30}
		index := Index(arr, func(x int) bool { return x == 30 })
		assert.Equal(t, 2, index)
	})
}

func TestDecodeHex(t *testing.T) {
	t.Run("valid IPv4 address", func(t *testing.T) {
		// 0100007F represents 127.0.0.1 in little-endian hex
		result, err := DecodeHex("0100007F")
		assert.NoError(t, err)
		assert.Equal(t, "127.0.0.1", result)
	})

	t.Run("another valid IPv4 address", func(t *testing.T) {
		// C0A80001 represents 192.168.0.1 in little-endian hex
		result, err := DecodeHex("0100A8C0")
		assert.NoError(t, err)
		assert.Equal(t, "192.168.0.1", result)
	})

	t.Run("invalid hex string", func(t *testing.T) {
		_, err := DecodeHex("ZZZZ")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error converting hex to int")
	})

	t.Run("odd length hex string", func(t *testing.T) {
		// Should still work as long as we process pairs
		result, err := DecodeHex("010000")
		assert.NoError(t, err)
		assert.Equal(t, "0.0.1", result)
	})

	t.Run("empty string", func(t *testing.T) {
		result, err := DecodeHex("")
		assert.NoError(t, err)
		assert.Equal(t, "", result)
	})

	t.Run("two byte hex", func(t *testing.T) {
		result, err := DecodeHex("0A0B")
		assert.NoError(t, err)
		assert.Equal(t, "11.10", result)
	})
}

func TestParseHexAddr(t *testing.T) {
	t.Run("valid address", func(t *testing.T) {
		// Format: IP:PORT where IP is hex little-endian and PORT is hex
		addr := "0100007F:0050"  // 127.0.0.1:80
		ip, port, err := ParseHexAddr(addr)
		assert.NoError(t, err)
		assert.Equal(t, "127.0.0.1", ip)
		assert.Equal(t, 80, port)
	})

	t.Run("another valid address", func(t *testing.T) {
		addr := "0100A8C0:1F90"  // 192.168.0.1:8080
		ip, port, err := ParseHexAddr(addr)
		assert.NoError(t, err)
		assert.Equal(t, "192.168.0.1", ip)
		assert.Equal(t, 8080, port)
	})

	t.Run("invalid format - no colon", func(t *testing.T) {
		_, _, err := ParseHexAddr("0100007F")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error splitting host and port")
	})

	t.Run("invalid hex IP", func(t *testing.T) {
		_, _, err := ParseHexAddr("ZZZZ:0050")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error decoding hex IP address")
	})

	t.Run("invalid hex port", func(t *testing.T) {
		_, _, err := ParseHexAddr("0100007F:ZZZZ")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error decoding hex port")
	})

	t.Run("empty string", func(t *testing.T) {
		_, _, err := ParseHexAddr("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error splitting host and port")
	})
}

func TestGetFreePort(t *testing.T) {
	t.Run("returns valid port", func(t *testing.T) {
		port, err := GetFreePort()
		assert.NoError(t, err)
		assert.Greater(t, port, 0)
		assert.Less(t, port, 65536)
	})

	t.Run("port is actually available", func(t *testing.T) {
		port, err := GetFreePort()
		require.NoError(t, err)
		
		// Try to bind to the port to verify it's available
		addr := fmt.Sprintf("localhost:%d", port)
		listener, err := net.Listen("tcp", addr)
		assert.NoError(t, err)
		if listener != nil {
			_ = listener.Close()
		}
	})

	t.Run("multiple calls return different ports", func(t *testing.T) {
		port1, err1 := GetFreePort()
		port2, err2 := GetFreePort()
		
		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NotEqual(t, port1, port2)
	})
}

func TestFileExists(t *testing.T) {
	t.Run("existing file", func(t *testing.T) {
		// Create a temporary file
		tmpDir := t.TempDir()
		tmpFile := filepath.Join(tmpDir, "test.txt")
		err := os.WriteFile(tmpFile, []byte("test"), 0644)
		require.NoError(t, err)
		
		assert.True(t, fileExists(tmpFile))
	})

	t.Run("non-existing file", func(t *testing.T) {
		assert.False(t, fileExists("/non/existent/file.txt"))
	})

	t.Run("directory exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		assert.True(t, fileExists(tmpDir))
	})
}

func TestLoadOrGenerateCert(t *testing.T) {
	// Save original working directory
	originalWd, err := os.Getwd()
	require.NoError(t, err)

	t.Run("snake oil mode - files exist", func(t *testing.T) {
		// Skip this test as it requires root access to create files in /etc/ssl/
		t.Skip("Skipping snake oil test as it requires root access")
	})

	t.Run("snake oil mode - files don't exist", func(t *testing.T) {
		_, _, err := LoadOrGenerateCert(true)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "snake oil certificate or key not found")
	})

	t.Run("generate new certificate", func(t *testing.T) {
		// Create temporary directory and change to it
		tmpDir := t.TempDir()
		err := os.Chdir(tmpDir)
		require.NoError(t, err)
		defer func() { _ = os.Chdir(originalWd) }()

		certPath, keyPath, err := LoadOrGenerateCert(false)
		assert.NoError(t, err)
		
		// Verify files were created
		assert.True(t, fileExists(certPath))
		assert.True(t, fileExists(keyPath))
		
		// Verify certificate can be loaded
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		assert.NoError(t, err)
		assert.NotNil(t, cert)
	})

	t.Run("load existing certificate", func(t *testing.T) {
		// Create temporary directory and change to it
		tmpDir := t.TempDir()
		err := os.Chdir(tmpDir)
		require.NoError(t, err)
		defer func() { _ = os.Chdir(originalWd) }()

		// First call - generates certificate
		certPath1, keyPath1, err := LoadOrGenerateCert(false)
		require.NoError(t, err)
		
		// Second call - should load existing certificate
		certPath2, keyPath2, err := LoadOrGenerateCert(false)
		assert.NoError(t, err)
		assert.Equal(t, certPath1, certPath2)
		assert.Equal(t, keyPath1, keyPath2)
	})
}

func TestGenerateAndSaveCert(t *testing.T) {
	// Save original working directory
	originalWd, err := os.Getwd()
	require.NoError(t, err)

	t.Run("generates valid certificate", func(t *testing.T) {
		// Create temporary directory and change to it
		tmpDir := t.TempDir()
		err := os.Chdir(tmpDir)
		require.NoError(t, err)
		defer func() { _ = os.Chdir(originalWd) }()

		certPath, keyPath, err := generateAndSaveCert()
		assert.NoError(t, err)
		
		// Verify files exist
		assert.True(t, fileExists(certPath))
		assert.True(t, fileExists(keyPath))
		
		// Verify certificate is valid
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		assert.NoError(t, err)
		assert.NotNil(t, cert)
		
		// Parse and verify certificate details
		certData, err := os.ReadFile(certPath)
		require.NoError(t, err)
		
		block, _ := pem.Decode(certData)
		require.NotNil(t, block)
		
		parsedCert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		
		// Verify certificate properties
		assert.Equal(t, "go-webfilter", parsedCert.Subject.Organization[0])
		assert.Contains(t, parsedCert.DNSNames, "localhost")
		// Just verify we have at least one IP address in the certificate
		assert.True(t, len(parsedCert.IPAddresses) > 0, "Certificate should contain at least one IP address")
	})

	t.Run("creates build directory", func(t *testing.T) {
		// Create temporary directory and change to it
		tmpDir := t.TempDir()
		err := os.Chdir(tmpDir)
		require.NoError(t, err)
		defer func() { _ = os.Chdir(originalWd) }()

		_, _, err = generateAndSaveCert()
		assert.NoError(t, err)
		
		// Verify build directory was created
		assert.True(t, fileExists("build"))
	})
}

// Benchmark tests
func BenchmarkIndex(b *testing.B) {
	arr := make([]int, 1000)
	for i := range arr {
		arr[i] = i
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Index(arr, func(x int) bool { return x == 500 })
	}
}

func BenchmarkDecodeHex(b *testing.B) {
	hexString := "0100007F"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeHex(hexString)
	}
}

func BenchmarkParseHexAddr(b *testing.B) {
	addr := "0100007F:0050"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ParseHexAddr(addr)
	}
}

func BenchmarkGetFreePort(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetFreePort()
	}
}

// Table-driven tests for DecodeHex
func TestDecodeHexTableDriven(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "localhost",
			input:    "0100007F",
			expected: "127.0.0.1",
			wantErr:  false,
		},
		{
			name:     "192.168.1.1",
			input:    "0101A8C0",
			expected: "192.168.1.1",
			wantErr:  false,
		},
		{
			name:     "10.0.0.1",
			input:    "0100000A",
			expected: "10.0.0.1",
			wantErr:  false,
		},
		{
			name:     "invalid hex",
			input:    "GGGG",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeHex(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// Table-driven tests for ParseHexAddr
func TestParseHexAddrTableDriven(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedIP  string
		expectedPort int
		wantErr     bool
	}{
		{
			name:        "localhost:80",
			input:       "0100007F:0050",
			expectedIP:  "127.0.0.1",
			expectedPort: 80,
			wantErr:     false,
		},
		{
			name:        "192.168.0.1:8080",
			input:       "0100A8C0:1F90",
			expectedIP:  "192.168.0.1",
			expectedPort: 8080,
			wantErr:     false,
		},
		{
			name:        "10.0.0.1:443",
			input:       "0100000A:01BB",
			expectedIP:  "10.0.0.1",
			expectedPort: 443,
			wantErr:     false,
		},
		{
			name:        "invalid format",
			input:       "0100007F",
			expectedIP:  "",
			expectedPort: -1,
			wantErr:     true,
		},
		{
			name:        "invalid hex IP",
			input:       "ZZZZ:0050",
			expectedIP:  "",
			expectedPort: -1,
			wantErr:     true,
		},
		{
			name:        "invalid hex port",
			input:       "0100007F:ZZZZ",
			expectedIP:  "",
			expectedPort: -1,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, port, err := ParseHexAddr(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedIP, ip)
				assert.Equal(t, tt.expectedPort, port)
			}
		})
	}
}