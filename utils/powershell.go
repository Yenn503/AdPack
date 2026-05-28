package utils

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// EncodePowerShell returns a base64-encoded PowerShell command string safe for
// use with powershell -EncodedCommand. This prevents injection through special
// characters in user-supplied values (GPO names, OUs, commands, etc.).
//
// The command is encoded as UTF-16LE (Unicode) as required by PowerShell's
// -EncodedCommand flag.
func EncodePowerShell(cmd string) string {
	// PowerShell -EncodedCommand expects UTF-16LE encoded command
	utf16 := encodeUTF16LE(cmd)
	return base64.StdEncoding.EncodeToString(utf16)
}

// PowerShellCmd returns a complete powershell -EncodedCommand argument string
// ready for use with nxc -x or similar remote exec tools.
func PowerShellCmd(cmd string) string {
	return fmt.Sprintf("powershell -EncodedCommand %s", EncodePowerShell(cmd))
}

// encodeUTF16LE converts a Go string (UTF-8) to UTF-16LE bytes.
func encodeUTF16LE(s string) []byte {
	var b []byte
	for _, r := range s {
		if r <= 0xFFFF {
			b = append(b, byte(r), byte(r>>8))
		} else {
			// Surrogate pair for characters above BMP
			r -= 0x10000
			hi := 0xD800 + ((r >> 10) & 0x3FF)
			lo := 0xDC00 + (r & 0x3FF)
			b = append(b, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
		}
	}
	return b
}

// SanitizeFlag strips characters that could interfere with command-line
// argument parsing when a value is passed as a flag argument to nxc.
// This is a defense-in-depth measure for values that cannot use
// -EncodedCommand (e.g., simple single-command invocations).
func SanitizeFlag(s string) string {
	// Strip newlines, null bytes, and other control characters
	s = strings.Map(func(r rune) rune {
		if r < 32 && r != ' ' {
			return -1
		}
		return r
	}, s)
	// Escape double quotes
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
