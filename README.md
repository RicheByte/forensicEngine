## ⚠️Havent fully tested, if you are using this use in your Cation⚠️




## Key Features of the Combined Solution:

###  **Enhanced Capabilities:**

- **Universal Scanning**: Automatically detects whether target is file or directory
    
- **Directory Scanning**: Full recursive directory traversal with pattern matching
    
- **ML Confidence Scoring**: Advanced file validation with entropy analysis
    
- **Safety Features**: Malware detection, safe mode, and validation checks
    
- **Parallel Processing**: Multi-threaded for both single files and directories
    

###  **Directory Scanning Features:**

- Recursive and non-recursive directory traversal
    
- File pattern matching (`*.jpg`, `*.pdf`, etc.)
    
- Progress tracking and detailed reporting
    
- Individual output directories for each scanned file
    
- Comprehensive directory scan reports
    

###  **Usage Examples:**

```bash

# Single file carving (traditional)
python zeta_carver_pro.py disk_image.img -o ./recovered

# Directory scanning
python zeta_carver_pro.py /home/user/documents -o ./carved_files --dir-scan

# Recursive scanning with pattern
python zeta_carver_pro.py /home/user -o ./recovery --dir-scan --recursive --pattern "*.jpg"

# Universal auto-detection
python zeta_carver_pro.py /path/to/target -o ./output --universal

# Safe preview mode
python zeta_carver_pro.py disk_image.img -o ./preview --safe
```

###  **Safety & Security:**

- YARA malware scanning integration
    
- Safe mode for preview without file writing
    
- Header validation and entropy checking
    
- Duplicate file detection via SHA-256 hashing
    
- SQLite database for recovery session tracking
    

