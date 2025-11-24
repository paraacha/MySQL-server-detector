package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

func main() {
	// Read `ip` and `port` from command-line flags. Defaults to localhost:3306.
	ipFlag := flag.String("ip", "127.0.0.1", "IP address of MySQL server")
	portFlag := flag.String("port", "3306", "Port number")
	flag.Parse()
	checkMySQL(*ipFlag, *portFlag)
}

// Checks MySQL server availability on specified IP and port. Tested on MySQL 5.x+ servers.
// @todo: Test on MySQL < 5.x servers, should work without code changes.
func checkMySQL(ip string, port string) {
	// --- Validate input ----------------------------------------------------
	if net.ParseIP(ip) == nil {
		fmt.Printf("Error: Input IP address '%s' is not formatted properly.\n", ip)
		return
	}

	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		fmt.Printf("Error: Input Port '%s' is not in valid range (1-65535).\n", port)
		return
	}

	// --- Establish TCP connection -----------------------------------------
	address := net.JoinHostPort(ip, port)
	connTimeout := 5 * time.Second // Hardcoded timeout
	conn, err := net.DialTimeout("tcp", address, connTimeout)
	if err != nil {
		fmt.Printf("Unable to detect MySQL. Port %s on %s is closed or unreachable: %v\n", port, ip, err)
		return
	}
	defer conn.Close()
	fmt.Printf("Port %s on [%s] is OPEN...\n", port, ip)

	// --- Read single MySQL packet (sufficient for handshake) -----------------------------
	payload, err := readMySQLPacket(conn)
	if err != nil {
		fmt.Printf("Unable to detect MySQL. Error reading packet: %v\n", err)
		return
	}

	// --- Parse handshake basics -------------------------------------------
	offset := 0
	if len(payload) < 1 {
		fmt.Println("Unable to detect MySQL. Handshake payload too short")
		return
	}
	protocolVersion := payload[offset]
	if protocolVersion < 9 {
		fmt.Printf("Unable to detect MySQL. Unsupported protocol version? %d\n", protocolVersion)
		return
	}
	offset++

	serverVersion, newOff := readNullTerminatedString(payload, offset)
	offset = newOff

	if offset+4 > len(payload) {
		fmt.Println("Unable to detect MySQL. Unexpected end of payload while reading connection id")
		return
	}
	connID := int(payload[offset]) | int(payload[offset+1])<<8 | int(payload[offset+2])<<16 | int(payload[offset+3])<<24
	offset += 4

	fmt.Println("MySQL Server DETECTED")
	fmt.Printf("Protocol Version: %d\n", protocolVersion)
	fmt.Printf("Server Version: %s\n", serverVersion)
	fmt.Printf("Connection ID: %d\n", connID)

	// Protocol v9 has limited handshake information — stop early if we receive it by any chance
	if protocolVersion == 9 {
		return
	}

	// --- Prepare structures and maps used for printing --------------------
	// @todo: Verify and expand character set map as needed
	charSetMap := map[byte]string{
		1:   "big5_chinese_ci",
		8:   "latin1_swedish_ci",
		33:  "utf8_general_ci",
		45:  "utf8mb4_general_ci",
		63:  "binary",
		83:  "utf8mb4_0900_ai_ci",
		192: "utf8mb4_unicode_520_ci",
		255: "utf8mb4_0900_ai_ci",
	}

	// Skip 8 bytes of auth-plugin-data-part-1
	offset += 8

	// Skip 1 filler byte
	offset++

	// capability flags (low 2 bytes)
	if offset+2 > len(payload) {
		fmt.Println("Unexpected end while reading capability flags low")
		return
	}
	capabilityFlagsLow := int(payload[offset]) | int(payload[offset+1])<<8
	offset += 2

	// character set
	if offset+1 > len(payload) {
		fmt.Println("Unexpected end while reading character set")
		return
	}
	characterSet := payload[offset]
	offset++

	// status flags
	if offset+2 > len(payload) {
		fmt.Println("Unexpected end while reading status flags")
		return
	}
	statusFlags := int(payload[offset]) | int(payload[offset+1])<<8
	offset += 2

	// capability flags (high 2 bytes)
	if offset+2 > len(payload) {
		fmt.Println("Unexpected end while reading capability flags high")
		return
	}
	capabilityFlagsHigh := int(payload[offset]) | int(payload[offset+1])<<8
	capabilityFlags := capabilityFlagsLow | (capabilityFlagsHigh << 16)
	offset += 2

	// auth-plugin-data length
	if offset+1 > len(payload) {
		fmt.Println("Unexpected end while reading auth plugin data length")
		return
	}
	authPluginDataLen := int(payload[offset])
	offset++

	// skip 10 reserved bytes
	offset += 10

	pluginName := "N/A"
	// plugin name only matters if (capabilities & CLIENT_PLUGIN_AUTH) is set
	if authPluginDataLen != 0 {
		// compute length of auth-plugin-data-part-2
		authPluginDataPart2Len := authPluginDataLen - 8
		if authPluginDataPart2Len < 13 {
			authPluginDataPart2Len = 13
		}

		// @todo: potential buffer overflow check here? not an issue atm., we skip auth-plugin-data-part-2

		// skip auth-plugin-data-part-2
		offset += authPluginDataPart2Len

		// plugin name (null terminated)
		pn, _ := readNullTerminatedString(payload, offset)
		pluginName = pn
	}

	// Print collected information
	fmt.Println("--- MySQL 4.x+ Handshake Info ---")
	charSetName := charSetMap[characterSet]
	if charSetName == "" {
		charSetName = "unknown"
	}
	fmt.Printf("Character Set: %d (%s)\n", characterSet, charSetName)
	fmt.Printf("Capabilities (combined): %032b\n", uint32(capabilityFlags))
	fmt.Printf("Status Flags: %016b\n", uint16(statusFlags))
	fmt.Printf("Auth Plugin Name: %s\n", pluginName)
}

// readMySQLPacket reads a single MySQL packet from the connection.
// MySQL packet header is 4 bytes: 3 bytes length (little-endian) + 1 byte sequence (sufficient for handshake).
func readMySQLPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // Hardcoded timeouts
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}

	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length <= 0 {
		return nil, fmt.Errorf("invalid length: %d", length)
	}

	payload := make([]byte, length)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second)) // Hardcoded timeouts
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, fmt.Errorf("reading payload: %w", err)
	}
	return payload, nil
}

// readNullTerminatedString returns the string starting at offset and the offset
// immediately after the terminating NUL byte. If no NUL found, it returns the
// remainder of the slice and len(payload).
func readNullTerminatedString(payload []byte, offset int) (string, int) {
	if offset >= len(payload) {
		return "", offset
	}

	end := offset
	for end < len(payload) && payload[end] != 0 {
		end++
	}

	s := string(payload[offset:end])
	if end < len(payload) {
		end++ // skip the terminating NUL
	}
	return s, end
}
