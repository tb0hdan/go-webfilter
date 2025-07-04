package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func Index[T any](arr []T, f func(T) bool) int {
	for i, item := range arr {
		if f(item) {
			return i
		}
	}

	return -1
}

func DecodeHex(s string) (string, error) {
	parts := make([]string, 0, len(s)/2)
	// Convert hex string to byte slice
	for i := 0; i < len(s); i += 2 {
		part, err := strconv.ParseInt(s[i:i+2], 16, 64)
		if err != nil {
			return "", fmt.Errorf("error converting hex to int: %w", err)
		}
		parts = append(parts, fmt.Sprintf("%d", part))
	}
	// Reverse the parts
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	// Print the resulting parts
	return strings.Join(parts, "."), nil
}

func ParseHexAddr(addr string) (string, int, error) {
	localIP, localPort, err := net.SplitHostPort(addr)
	if err != nil {
		return "", -1, fmt.Errorf("error splitting host and port: %w", err)
	}
	// Decode the hex IP address
	decodedIP, err := DecodeHex(localIP)
	if err != nil {
		return "", -1, fmt.Errorf("error decoding hex IP address: %w", err)
	}
	// decode the port
	portNum, err := strconv.ParseInt(localPort, 16, 64)
	if err != nil {
		return "", -1, fmt.Errorf("error decoding hex port: %w", err)
	}
	return decodedIP, int(portNum), nil
}
