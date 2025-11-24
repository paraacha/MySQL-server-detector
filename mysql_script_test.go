package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Test data: multiple expected substrings for each IP/port
var testCases = []struct {
	ip       string
	port     string
	expected []string // all substrings that should appear in the output
}{
	{
		"127.0.0.1", "9991",
		[]string{
			"Server Version: 9.1", // @todo add more checks
		},
	},
	{
		"127.0.0.1", "9981",
		[]string{
			"Server Version: 8.1", // @todo add more checks
		},
	},
	{
		"127.0.0.1", "9955",
		[]string{
			"Server Version: 5.5", // @todo add more checks
		},
	},
	{
		"127.0.0.1", "9957",
		[]string{
			"Server Version: 5.7", // @todo add more checks
		},
	},
}

// captureStdout captures everything printed to stdout while f() runs
func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

func TestCheckMySQL(t *testing.T) {
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s:%s", tc.ip, tc.port), func(t *testing.T) {
			output := captureStdout(func() {
				checkMySQL(tc.ip, tc.port)
			})

			for _, substr := range tc.expected {
				if !strings.Contains(output, substr) {
					t.Errorf("Expected output to contain '%s', got:\n%s", substr, output)
				}
			}
		})
	}
}
