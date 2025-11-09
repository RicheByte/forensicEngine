

## Forensic Engine

A comprehensive suite of forensic analysis and security testing tools for authorized penetration testing and security research.

##  Quick Start

### Windows (Recommended)
Simply double-click `launcher.bat` to start the interactive menu!

Or run in PowerShell:
```powershell
.\launcher.ps1
```

### Linux/Mac
```bash
chmod +x why.sh
./why.sh
```

##  Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/RicheByte/forensicEngine.git
   cd forensicEngine
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Launch the tool**
   - Windows: Double-click `launcher.bat`
   - Linux/Mac: Run `./why.sh`

##  Available Tools

### 1. **cracker.py** - Hash Identifier & Cracker
Advanced hash identification and cracking tool with ML-based pattern recognition.

**Features:**
- Identifies 15+ hash types (MD5, SHA1, SHA256, BCrypt, NTLM, etc.)
- Multiple cracking methods (wordlist, rules, brute-force, rainbow tables)
- AI-assisted confidence scoring
- Bulk hash processing
- Session tracking

**Example Usage:**
```bash
# Identify a hash
python cracker.py "5d41402abc4b2a76b9719d911017c592" --identify

# Crack a hash
python cracker.py "5d41402abc4b2a76b9719d911017c592" --crack

# Bulk analysis
python cracker.py hashes.txt --bulk --output ./results
```

### 2. **FileCarver.py** - Quantum File Carver
File recovery and carving tool with ML confidence scoring and YARA scanning.

**Features:**
- Recovers 18+ file types (JPEG, PNG, PDF, ZIP, EXE, etc.)
- ML-based confidence scoring
- Directory scanning (recursive/non-recursive)
- YARA malware detection
- Entropy analysis
- Safe mode for previewing

**Example Usage:**
```bash
# Carve files from disk image
python FileCarver.py disk_image.img -o ./recovered

# Scan directory recursively
python FileCarver.py /home/user/documents --dir-scan --recursive -o ./carved

# Safe preview mode
python FileCarver.py suspicious_file.bin -o ./preview --safe
```

### 3. **vmescapetester.py** - VM Escape Tester
Hypervisor vulnerability assessment and VM escape testing platform.

**Features:**
- Detects VMware, VirtualBox, KVM, Hyper-V, Xen, Docker
- Tests 12+ escape vectors and CVEs
- Side-channel attack simulation
- Memory protection assessment
- Spectre/Meltdown detection
- Comprehensive security reports

**Example Usage:**
```bash
# Comprehensive assessment (safe mode)
python vmescapetester.py --comprehensive --safe

# Detection only
python vmescapetester.py --detection-only

# Real testing (requires authorization)
python vmescapetester.py --comprehensive --no-safe
```

### 4. **wipier.py** - Log Tamperer/Sanitizer
Ethical log obfuscation and secure wiping tool with forensic resistance.

**Features:**
- Obfuscates IPs, emails, passwords, tokens
- Supports Apache, Nginx, Syslog, Auth, JSON logs
- Multi-pass secure wiping (DoD 5220.22-M compliant)
- Batch directory processing
- YARA-based sensitive data detection
- Audit trail database

**Example Usage:**
```bash
# Obfuscate log file (safe preview)
python wipier.py /var/log/auth.log --operation OBFUSCATE --safe

# Sanitize and wipe
python wipier.py /var/log/apache2/access.log --operation SANITIZE --no-safe

# Batch process directory
python wipier.py /var/log --dir-scan --pattern "*.log" --operation OBFUSCATE
```

##  Launcher Features

The PowerShell launcher (`launcher.ps1`) provides:
-  Interactive menu system with color-coded options
-  Python environment verification
-  Automatic package installation
-  Help display for all tools
-  Custom argument execution
-  File explorer integration
-  Error handling and user-friendly messages

##  Legal Disclaimer

**IMPORTANT: AUTHORIZED USE ONLY**

These tools are designed for:
- Authorized penetration testing
- Security research and education
- Forensic analysis with proper authorization
- Legitimate privacy protection

**You MUST have explicit authorization before using these tools on any system you do not own.**

Unauthorized use may violate:
- Computer Fraud and Abuse Act (CFAA)
- Digital Millennium Copyright Act (DMCA)
- State and local computer crime laws
- International cybersecurity regulations

The authors and contributors assume NO LIABILITY for misuse of these tools.

##  Security Notice

- Always use `--safe` mode first to preview operations
- Create backups before running destructive operations
- Review all command arguments carefully
- Keep audit logs of all activities
- Ensure proper authorization documentation

##  Requirements

- **Python**: 3.7 or higher
- **Operating System**: Windows 10/11, Linux, macOS
- **Privileges**: Some operations may require administrator/root privileges
- **Dependencies**: Listed in `requirements.txt`

### Core Dependencies
```
numpy>=1.21.0
pandas>=1.3.0
psutil>=5.8.0
netifaces>=0.11.0
```

### Optional Dependencies
```
yara-python>=4.0.0  # For pattern matching and malware detection
```

##  Educational Use

This project is excellent for:
- Learning forensic analysis techniques
- Understanding cryptographic hash functions
- Studying file system structures
- Exploring VM security and hypervisor detection
- Practicing ethical hacking methodologies

##  Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with clear commit messages
4. Test thoroughly
5. Submit a pull request

##  Documentation

Each tool includes comprehensive `--help` documentation:
```bash
python cracker.py --help
python FileCarver.py --help
python vmescapetester.py --help
python wipier.py --help
```

##  Troubleshooting

### Python Not Found
Ensure Python is installed and added to PATH:
```bash
python --version
```

### Missing Modules
Install requirements:
```bash
pip install -r requirements.txt
```

### Permission Errors
Run with elevated privileges:
- Windows: Run as Administrator
- Linux/Mac: Use `sudo` where appropriate

### PowerShell Execution Policy
If `launcher.ps1` won't run:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

##  Version History

- **v2.0** - PowerShell launcher with enhanced connectivity
- **v1.0** - Initial release with bash launcher

##  Contact

- **Author**: RicheByte
- **Repository**: [forensicEngine](https://github.com/RicheByte/forensicEngine)
- **Issues**: Submit via GitHub Issues


Happy Hacking! ❤️
