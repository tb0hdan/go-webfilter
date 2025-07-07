package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	certDir          = "build"
	certFile         = "server.crt"
	keyFile          = "server.key"
	snakeOilCertFile = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
	snakeOilKeyFile  = "/etc/ssl/private/ssl-cert-snakeoil.key"
)

// LoadOrGenerateCert loads existing certificate from disk or generates a new one if missing
func LoadOrGenerateCert(snakeOil bool) (string, string, error) {
	if snakeOil {
		// Use the snake oil certificate if specified
		if fileExists(snakeOilCertFile) && fileExists(snakeOilKeyFile) {
			return snakeOilCertFile, snakeOilKeyFile, nil
		}
		return "", "", fmt.Errorf("snake oil certificate or key not found at %s or %s", snakeOilCertFile, snakeOilKeyFile)
	}
	// Use the custom certificate directory and files
	certPath := filepath.Join(certDir, certFile)
	keyPath := filepath.Join(certDir, keyFile)

	// Check if both files exist
	if fileExists(certPath) && fileExists(keyPath) {
		_, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil {
			return certPath, keyPath, nil
		}
		// If loading fails, regenerate
		fmt.Printf("Failed to load certificate: %v. Regenerating...\n", err)
	}

	// Generate new certificate
	return generateAndSaveCert()
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// generateAndSaveCert generates a new certificate and saves it to disk
func generateAndSaveCert() (string, string, error) {
	// Ensure directory exists
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create cert directory: %w", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"go-webfilter"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	// Save certificate
	certPath := filepath.Join(certDir, certFile)
	certOut, err := os.Create(certPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to create cert file: %w", err)
	}
	defer func() {
		if err := certOut.Close(); err != nil {
			fmt.Printf("Warning: failed to close certificate file: %v\n", err)
		}
	}()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return "", "", fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key
	keyPath := filepath.Join(certDir, keyFile)
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to create key file: %w", err)
	}
	defer func() {
		if err := keyOut.Close(); err != nil {
			fmt.Printf("Warning: failed to close key file: %v\n", err)
		}
	}()

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return "", "", fmt.Errorf("failed to write private key: %w", err)
	}

	// Load the certificate from the saved files
	return certPath, keyPath, nil
}
