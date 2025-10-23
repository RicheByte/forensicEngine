

## forensicEngine
A comprehensive Python-based forensic analysis and post-exploitation toolkit for security researchers, penetration testers, and digital forensics professionals. This suite provides advanced capabilities for file recovery, hash analysis, VM escape testing, and log forensics.

##  Features

###  FileCarver.py - Quantum File Recovery Engine
Advanced file carving tool with ML-enhanced confidence scoring and forensic validation.

**Key Capabilities:**
- **Multi-format Support**: JPEG, PNG, PDF, ZIP, RAR, MP3, MP4, EXE, ELF, DOC, and more
- **ML Confidence Scoring**: AI-inspired confidence calculation for recovered files
- **Directory Scanning**: Recursive and non-recursive directory analysis
- **YARA Integration**: Malware detection during recovery
- **Entropy Analysis**: File validation through Shannon entropy calculation
- **Parallel Processing**: Multi-threaded carving for performance
- **SQLite Database**: Session tracking and recovery history

**Usage:**
```bash
# Single file carving
python FileCarver.py disk_image.img -o ./recovered

# Directory scanning (recursive)
python FileCarver.py /path/to/data -o ./carved --dir-scan --recursive

# Universal auto-detection mode
python FileCarver.py /target -o ./output --universal --threads 8
```

###  cracker.py - Hash Identifier & Cracker
Quantum cryptographic analysis platform for hash identification and password recovery.

**Key Capabilities:**
- **Hash Type Detection**: MD5, SHA1, SHA256, SHA512, BCrypt, NTLM, MySQL, JWT, and more
- **AI-Enhanced Analysis**: Pattern recognition with confidence scoring
- **Multiple Attack Modes**: Wordlist, rules-based, brute-force, rainbow tables
- **Bulk Processing**: Parallel hash analysis with threading
- **Entropy Analysis**: Shannon entropy for hash validation
- **SQLite Tracking**: Session and result database storage

**Supported Hash Types:**
- MD5, SHA1, SHA256, SHA512
- BCrypt, NTLM, LM Hash
- MD5Crypt, SHA256Crypt, SHA512Crypt
- Apache MD5, MySQL 4.1+
- JWT tokens, Base64, Hex encoding

**Usage:**
```bash
# Identify hash type
python cracker.py "5d41402abc4b2a76b9719d911017c592" --identify

# Crack with all methods
python cracker.py "hash_value" --crack --methods wordlist,bruteforce

# Bulk hash analysis
python cracker.py hashes.txt --bulk --output ./results
```

###  vmescapetester.py - VM Escape Vulnerability Tester
Hypervisor vulnerability assessment and VM escape testing platform.

**Key Capabilities:**
- **Hypervisor Detection**: VMware, VirtualBox, KVM, Hyper-V, Xen, Docker
- **Multi-technique Fingerprinting**: CPUID, MAC address, DMI, process, file system analysis
- **CVE Exploitation**: Tests for known VM escape vulnerabilities
- **Side-Channel Attacks**: Spectre, Meltdown, timing analysis
- **Memory Protection Assessment**: ASLR, SMEP, SMAP, PTI checks
- **Comprehensive Reporting**: JSON reports with recommendations

**Tested Attack Vectors:**
- CVE-2021-21974 (VMware vSphere RCE)
- CVE-2020-14364 (KVM Privilege Escalation)
- CVE-2019-3887 (Xen IOMMU Bypass)
- Spectre/Meltdown variants
- Memory corruption exploits
- DMA attacks

**Usage:**
```bash
# Comprehensive assessment (safe mode)
python vmescapetester.py --comprehensive --safe

# Stealth assessment
python vmescapetester.py --hypervisor auto --stealth

# Detection only
python vmescapetester.py --detection-only
```

###  wipier.py - Log Tampering & Forensic Obfuscation
Ethical trace obfuscation system for authorized security testing.

**Key Capabilities:**
- **Log Format Detection**: Apache, Nginx, Syslog, Auth logs, JSON
- **Intelligent Obfuscation**: IP addresses, user agents, emails, credentials
- **Secure Wiping**: Multi-pass forensic-resistant file deletion
- **Batch Processing**: Parallel processing of entire log directories
- **YARA Pattern Detection**: Identifies sensitive data for obfuscation
- **Audit Trail**: SQLite database tracking all operations

**Operations:**
- **OBFUSCATE**: Replace sensitive data with realistic fake data
- **SANITIZE**: Obfuscate then securely wipe
- **WIPE**: Complete forensic destruction

**Usage:**
```bash
# Obfuscate single log (safe preview)
python wipier.py /var/log/auth.log --operation OBFUSCATE --safe

# Batch directory processing
python wipier.py /var/log --dir-scan --pattern "*.log" --recursive

# Maximum forensic cleanup
python wipier.py sensitive.log --operation WIPE --wipe-passes 7
```

##  Requirements

```bash
pip install -r requirements.txt
```

**Optional Dependencies:**
- `yara-python` - For YARA rule scanning
- `numpy` - For ML-enhanced analysis
- `pandas` - For advanced data processing
- `psutil` - For system information
- `netifaces` - For network interface detection

##  Security Notice

**FOR AUTHORIZED USE ONLY**

This toolkit is designed for:
- Authorized penetration testing
- Digital forensics investigation
- Security research and education
- Incident response and recovery

**Legal Disclaimer:**
- Ensure you have **proper authorization** before using these tools
- Unauthorized use may violate laws and regulations
- Use responsibly and ethically
- The authors are not responsible for misuse

##  Safe Mode

All tools include **Safe Mode** by default:
- Preview operations without making changes
- Test configurations safely
- Verify targets before execution
- Disable with `--no-safe` flag when authorized

##  Features Overview

| Tool | Purpose | Key Features |
|------|---------|-------------|
| FileCarver | File Recovery | ML confidence, YARA scanning, 15+ formats |
| cracker | Hash Analysis | 15+ hash types, 4 attack modes, bulk processing |
| vmescapetester | VM Security | CVE testing, side-channel attacks, 6+ hypervisors |
| wipier | Log Forensics | 3 operations, smart obfuscation, batch processing |

##  Advanced Configuration

Each tool supports:
- **Multi-threading**: Parallel processing for performance
- **Database Tracking**: SQLite session management
- **Comprehensive Reporting**: JSON output with detailed metrics
- **Entropy Analysis**: Shannon entropy for validation
- **Pattern Recognition**: YARA and regex-based detection

##  Documentation

Each tool includes detailed help:
```bash
python <tool>.py --help
```

##  Use Cases

- **Digital Forensics**: Recover deleted files, analyze disk images
- **Penetration Testing**: VM escape testing, hash cracking
- **Incident Response**: Log analysis, evidence collection
- **Security Research**: Vulnerability assessment, cryptographic analysis
- **Privacy Protection**: Authorized data sanitization

##  Ethical Guidelines

1. **Authorization First**: Always obtain proper authorization
2. **Safe Mode Testing**: Test with `--safe` before actual operations
3. **Audit Trails**: Maintain logs of all operations
4. **Responsible Disclosure**: Report vulnerabilities responsibly
5. **Legal Compliance**: Follow all applicable laws and regulations



##  Contributing

This is a specialized security toolkit. Contributions should focus on:
- Enhanced forensic capabilities
- Additional hash/file format support
- Improved ML/AI detection
- Security vulnerability research

---

Happy Hacking! ❤️
