package authforge

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"runtime"
)

func generateHWID() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "hostname-unavailable"
	}

	macAddress := "mac-unavailable"
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			if len(iface.HardwareAddr) == 0 {
				continue
			}
			macAddress = iface.HardwareAddr.String()
			break
		}
	}

	material := hostname + "|" + runtime.GOOS + "|" + runtime.GOARCH + "|" + macAddress
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}
