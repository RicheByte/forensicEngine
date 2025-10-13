#!/usr/bin/env python3
"""
ZETA REALM QUANTUM FILE CARVER v3.1
Enhanced with directory scanning, ML confidence, safety features, and YARA scanning
Created by Zo under command of Alpha - Omnipotent of Zeta Realm
"""

import os
import argparse
import mmap
import hashlib
import math
import threading
import sqlite3
import json
import time
import re
import fnmatch
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional, Set
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from collections import defaultdict
import struct

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("⚠️  YARA not available - install with 'pip install yara-python'")

@dataclass
class CarvedFile:
    """Enhanced carved file metadata with ML confidence"""
    offset: int
    size: int
    file_type: str
    signature: str
    hash_sha256: str
    hash_md5: str
    confidence: float
    entropy: float
    yara_matches: List[str]
    recovered: bool = False
    validated: bool = False

class QuantumZetaCarverPro:
    def __init__(self, safe_mode: bool = False):
        self.safe_mode = safe_mode
        self.fucking_quantum_signatures = self._load_quantum_signatures()
        self.header_whitelist = self._create_header_whitelist()
        self.carved_files: List[CarvedFile] = []
        self.carved_hashes: Set[str] = set()
        self.scanned_directories = set()
        self.lock = threading.Lock()
        self.yara_rules = None
        self.db_conn = None
        self._init_database()
        self._load_yara_rules()
        
        self.stats = {
            'total_scanned': 0,
            'files_carved': 0,
            'bytes_recovered': 0,
            'validated_files': 0,
            'start_time': 0,
            'file_types': defaultdict(int),
            'malware_detected': 0,
            'directories_scanned': 0,
            'files_processed': 0,
            'total_target_files': 0
        }
    
    def _init_database(self):
        """Initialize SQLite database for tracking recovery sessions"""
        self.db_conn = sqlite3.connect('zeta_recovery.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS recovery_sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                input_file TEXT,
                output_dir TEXT,
                parameters TEXT,
                total_files INTEGER,
                total_bytes INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS carved_files (
                file_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                offset INTEGER,
                size INTEGER,
                file_type TEXT,
                hash_sha256 TEXT,
                hash_md5 TEXT,
                confidence REAL,
                entropy REAL,
                validated BOOLEAN,
                yara_matches TEXT,
                recovery_time TEXT,
                FOREIGN KEY (session_id) REFERENCES recovery_sessions (session_id)
            )
        ''')
        
        self.db_conn.commit()
    
    def _load_yara_rules(self):
        """Load YARA rules for file classification and malware detection"""
        if not YARA_AVAILABLE:
            return
            
        try:
            rules = '''
            rule JPEG_file {
                strings:
                    $jpeg_header = { FF D8 FF }
                condition:
                    $jpeg_header at 0
            }
            
            rule PDF_file {
                strings:
                    $pdf_header = "%PDF-"
                condition:
                    $pdf_header at 0
            }
            
            rule ZIP_file {
                strings:
                    $zip_header = "PK"
                condition:
                    $zip_header at 0
            }
            
            rule Executable_file {
                strings:
                    $exe_header = "MZ"
                condition:
                    $exe_header at 0
            }
            
            rule Script_file {
                strings:
                    $shebang = "#!/"
                condition:
                    $shebang at 0
            }
            
            rule Suspicious_JavaScript {
                strings:
                    $eval = "eval"
                    $unescape = "unescape"
                    $shellcode = /\\x[0-9a-f]{2}/
                condition:
                    any of them and filesize < 100KB
            }
            '''
            
            self.yara_rules = yara.compile(source=rules)
            print("🔒 YARA rules loaded successfully")
        except Exception as e:
            print(f"⚠️  Failed to load YARA rules: {e}")
    
    def _create_header_whitelist(self) -> Dict[str, List[bytes]]:
        """Create comprehensive header whitelist for validation"""
        return {
            'JPEG': [b'\xFF\xD8\xFF\xE0', b'\xFF\xD8\xFF\xE1', b'\xFF\xD8\xFF\xE8'],
            'PNG': [b'\x89PNG\r\n\x1a\n'],
            'GIF': [b'GIF87a', b'GIF89a'],
            'BMP': [b'BM'],
            'PDF': [b'%PDF-'],
            'ZIP': [b'PK\x03\x04'],
            'RAR': [b'Rar!\x1A\x07'],
            'MP3': [b'ID3', b'\xFF\xFB'],
            'MP4': [b'ftyp'],
            'EXE': [b'MZ'],
            'ELF': [b'\x7FELF'],
            'DOC': [b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'],
            'DOCX': [b'PK\x03\x04'],
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """FIXED: Proper Shannon entropy calculation using math.log2"""
        if len(data) == 0:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        
        return entropy
    
    def _validate_file_header(self, data: bytes, file_type: str) -> bool:
        """Validate file against header whitelist"""
        if file_type not in self.header_whitelist:
            return True  # Unknown type, can't validate
        
        expected_headers = self.header_whitelist[file_type]
        return any(data.startswith(header) for header in expected_headers)
    
    def _scan_with_yara(self, data: bytes) -> List[str]:
        """Scan file data with YARA rules"""
        if not YARA_AVAILABLE or self.yara_rules is None:
            return []
        
        try:
            matches = self.yara_rules.match(data=data)
            return [str(match) for match in matches]
        except Exception as e:
            print(f"⚠️  YARA scan failed: {e}")
            return []
    
    def _calculate_ml_confidence(self, data: bytes, file_type: str, entropy: float) -> float:
        """Machine Learning-inspired confidence scoring using multiple heuristics"""
        confidence_factors = []
        
        # 1. Header validation confidence
        header_valid = self._validate_file_header(data, file_type)
        confidence_factors.append(0.3 if header_valid else 0.0)
        
        # 2. Entropy-based confidence (different file types have different expected entropy)
        expected_entropy_ranges = {
            'JPEG': (6.5, 7.8),
            'PNG': (7.0, 8.0),
            'PDF': (4.5, 8.0),
            'ZIP': (7.5, 8.0),
            'TEXT': (3.0, 5.5),
        }
        
        expected_range = expected_entropy_ranges.get(file_type, (4.0, 8.0))
        if expected_range[0] <= entropy <= expected_range[1]:
            confidence_factors.append(0.3)
        else:
            # Partial credit if close to range
            distance = min(abs(entropy - expected_range[0]), abs(entropy - expected_range[1]))
            confidence_factors.append(max(0, 0.3 - distance * 0.1))
        
        # 3. Size-based confidence
        min_sizes = {'JPEG': 100, 'PNG': 8, 'PDF': 100, 'ZIP': 100}
        min_size = min_sizes.get(file_type, 50)
        if len(data) >= min_size:
            confidence_factors.append(0.2)
        else:
            confidence_factors.append(0.1)
        
        # 4. Structure validation confidence
        structure_score = self._validate_file_structure(data, file_type)
        confidence_factors.append(structure_score * 0.2)
        
        return min(1.0, sum(confidence_factors))
    
    def _validate_file_structure(self, data: bytes, file_type: str) -> float:
        """Validate file structure for specific file types"""
        try:
            if file_type == 'JPEG':
                # Check for JPEG end marker
                return 1.0 if b'\xFF\xD9' in data else 0.5
            
            elif file_type == 'PNG':
                # Check for PNG end chunk
                return 1.0 if b'IEND' in data else 0.5
            
            elif file_type == 'PDF':
                # Check for PDF end marker
                return 1.0 if b'%%EOF' in data[-1024:] else 0.5
            
            elif file_type == 'ZIP':
                # Check for ZIP end of central directory
                return 1.0 if b'PK\x05\x06' in data[-100:] else 0.5
            
            else:
                return 0.7  # Default medium confidence for unknown types
                
        except Exception:
            return 0.3  # Low confidence if validation fails
    
    def _fragment_reassembly_ml(self, fragments: List[Tuple[int, bytes]], file_type: str) -> Optional[bytes]:
        """ML-inspired fragment reassembly using sequence alignment heuristics"""
        if not fragments:
            return None
        
        # Sort fragments by offset
        fragments.sort(key=lambda x: x[0])
        
        # Simple reassembly: concatenate contiguous fragments
        reassembled = bytearray()
        current_end = fragments[0][0]
        
        for offset, data in fragments:
            # Check if this fragment overlaps or continues from previous
            if offset <= current_end:
                # Overlapping fragment, take the longer one
                overlap_start = offset - fragments[0][0]
                if len(data) > len(reassembled[overlap_start:]):
                    reassembled[overlap_start:overlap_start + len(data)] = data
            else:
                # Gap detected - fill with zeros or try to bridge
                gap_size = offset - current_end
                reassembled.extend(b'\x00' * gap_size)
                reassembled.extend(data)
            
            current_end = max(current_end, offset + len(data))
        
        return bytes(reassembled)
    
    def _safe_file_write(self, data: bytes, file_path: Path, file_type: str) -> bool:
        """Safely write file with validation and malware checks"""
        if self.safe_mode:
            print(f"🔒 SAFE MODE: Would write {len(data)} bytes to {file_path}")
            return False
        
        # Check for potentially malicious content
        yara_matches = self._scan_with_yara(data)
        if any('Suspicious' in match for match in yara_matches):
            print(f"🚨 MALWARE DETECTED in {file_path}! Skipping write.")
            self.stats['malware_detected'] += 1
            return False
        
        try:
            with open(file_path, 'wb') as f:
                f.write(data)
            
            # Verify write was successful
            if file_path.exists() and file_path.stat().st_size == len(data):
                return True
            else:
                print(f"❌ File write verification failed for {file_path}")
                return False
                
        except Exception as e:
            print(f"💥 Error writing file {file_path}: {e}")
            return False
    
    def _load_quantum_signatures(self) -> Dict[str, List[Tuple[bytes, bytes, Optional[bytes]]]]:
        """Load enhanced file signatures with ML support"""
        return {
            'JPEG': [(b'\xFF\xD8\xFF\xE0', b'\xFF\xD9', None)],
            'PNG': [(b'\x89PNG\r\n\x1a\n', b'IEND\xaeB`\x82', None)],
            'PDF': [(b'%PDF-', b'%%EOF', None)],
            'ZIP': [(b'PK\x03\x04', b'PK\x05\x06', None)],
            'GIF': [(b'GIF87a', b'\x00\x3B', None), (b'GIF89a', b'\x00\x3B', None)],
            'BMP': [(b'BM', None, None)],
            'MP3': [(b'\xFF\xFB', None, None), (b'ID3', None, None)],
            'MP4': [(b'ftyp', b'moov', None)],
            'AVI': [(b'RIFF', b'AVI ', None)],
            'DOC': [(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', None, None)],
            'PPT': [(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', None, None)],
            'XLS': [(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', None, None)],
            'RAR': [(b'Rar!\x1A\x07\x00', b'\xC4\x3D\x7B\x00\x40\x07\x00', None)],
            '7Z': [(b'7z\xBC\xAF\x27\x1C', None, None)],
            'EXE': [(b'MZ', None, None)],
            'ELF': [(b'\x7FELF', None, None)],
            'SWF': [(b'FWS', None, None), (b'CWS', None, None)],
            'FLV': [(b'FLV', None, None)],
            'SQLITE': [(b'SQLite format 3', None, None)],
            'TORRENT': [(b'd8:announce', None, None)],
        }
    
    def _smart_end_detection(self, mm: mmap.mmap, start: int, file_type: str, header: bytes) -> int:
        """Enhanced end detection with ML improvements"""
        max_size = self._get_max_file_size(file_type)
        file_size = len(mm)
        
        # Strategy 1: Footer-based detection
        footer = None
        for sig_header, sig_footer, _ in self.fucking_quantum_signatures.get(file_type, []):
            if sig_header == header and sig_footer:
                footer = sig_footer
                break
        
        if footer:
            footer_pos = mm.find(footer, start + len(header))
            if footer_pos != -1:
                return footer_pos + len(footer)
        
        # Strategy 2: Size-based detection with reasonable limits
        reasonable_sizes = {
            'JPEG': 50 * 1024 * 1024,  # 50MB
            'PNG': 100 * 1024 * 1024,   # 100MB
            'PDF': 500 * 1024 * 1024,   # 500MB
            'ZIP': 2 * 1024 * 1024 * 1024,  # 2GB
            'DEFAULT': 100 * 1024 * 1024  # 100MB default
        }
        
        max_reasonable = reasonable_sizes.get(file_type, reasonable_sizes['DEFAULT'])
        return min(start + max_reasonable, file_size)
    
    def _get_max_file_size(self, file_type: str) -> int:
        """Get maximum expected file size for type"""
        max_sizes = {
            'JPEG': 100 * 1024 * 1024,   # 100MB
            'PNG': 200 * 1024 * 1024,    # 200MB
            'PDF': 500 * 1024 * 1024,    # 500MB
            'ZIP': 2 * 1024 * 1024 * 1024,  # 2GB
            'DEFAULT': 100 * 1024 * 1024  # 100MB default
        }
        return max_sizes.get(file_type, max_sizes['DEFAULT'])
    
    def _quantum_carve_chunk_enhanced(self, mm: mmap.mmap, chunk_start: int, chunk_end: int, 
                                    chunk_id: int, output_dir: Path) -> List[CarvedFile]:
        """Enhanced quantum carving with ML confidence and safety checks"""
        chunk_files = []
        chunk_data = mm[chunk_start:chunk_end]
        
        print(f"⚡ Quantum thread {chunk_id} carving {len(chunk_data):,} bytes...")
        
        for file_type, signatures in self.fucking_quantum_signatures.items():
            for header, footer, _ in signatures:
                if header is None:
                    continue
                    
                pos = 0
                while True:
                    pos = chunk_data.find(header, pos)
                    if pos == -1:
                        break
                    
                    absolute_pos = chunk_start + pos
                    end_pos = self._smart_end_detection(mm, absolute_pos, file_type, header)
                    
                    if end_pos > absolute_pos + len(header):
                        file_data = mm[absolute_pos:end_pos]
                        entropy = self._calculate_entropy(file_data)
                        yara_matches = self._scan_with_yara(file_data)
                        
                        # Calculate ML confidence score
                        confidence = self._calculate_ml_confidence(file_data, file_type, entropy)
                        
                        # Only proceed if confidence is above threshold
                        if confidence > 0.3:  # Adjustable threshold
                            file_hash_sha256 = hashlib.sha256(file_data).hexdigest()
                            file_hash_md5 = hashlib.md5(file_data).hexdigest()
                            
                            with self.lock:
                                if file_hash_sha256 not in self.carved_hashes:
                                    self.carved_hashes.add(file_hash_sha256)
                                    
                                    carved_file = CarvedFile(
                                        offset=absolute_pos,
                                        size=len(file_data),
                                        file_type=file_type,
                                        signature=header.hex()[:8],
                                        hash_sha256=file_hash_sha256,
                                        hash_md5=file_hash_md5,
                                        confidence=confidence,
                                        entropy=entropy,
                                        yara_matches=yara_matches,
                                        validated=self._validate_file_header(file_data, file_type)
                                    )
                                    
                                    # Save file with safety checks
                                    if confidence > 0.6:  # Higher threshold for actual recovery
                                        filename = f"zeta_{file_type}_{absolute_pos:08x}_{confidence:.2f}.{file_type.lower()}"
                                        output_path = output_dir / filename
                                        
                                        if self._safe_file_write(file_data, output_path, file_type):
                                            carved_file.recovered = True
                                            self.stats['files_carved'] += 1
                                            self.stats['bytes_recovered'] += len(file_data)
                                            self.stats['file_types'][file_type] += 1
                                            
                                            if carved_file.validated:
                                                self.stats['validated_files'] += 1
                                            
                                            print(f"💾 Thread {chunk_id} carved {filename} "
                                                  f"({len(file_data):,} bytes, conf: {confidence:.2f})")
                                    
                                    chunk_files.append(carved_file)
                                    self._save_to_database(carved_file)
                    
                    pos += len(header)
            
        return chunk_files
    
    def _save_to_database(self, carved_file: CarvedFile):
        """Save carved file metadata to SQLite database"""
        if self.db_conn is None:
            return
            
        try:
            cursor = self.db_conn.cursor()
            cursor.execute('''
                INSERT INTO carved_files 
                (session_id, offset, size, file_type, hash_sha256, hash_md5, confidence, entropy, validated, yara_matches, recovery_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (1, carved_file.offset, carved_file.size, carved_file.file_type, 
                  carved_file.hash_sha256, carved_file.hash_md5, carved_file.confidence,
                  carved_file.entropy, carved_file.validated, 
                  json.dumps(carved_file.yara_matches), 
                  time.strftime('%Y-%m-%d %H:%M:%S')))
            
            self.db_conn.commit()
        except Exception as e:
            print(f"⚠️  Database error: {e}")
    
    # ==================== DIRECTORY SCANNING METHODS ====================
    
    def scan_directory(self, directory: str, output_dir: str, 
                      recursive: bool = False, file_pattern: str = "*",
                      threads: int = 8, min_confidence: float = 0.6) -> Dict:
        """
        Scan entire directory structure and carve files from all files found
        """
        print(f"""
        📁 ZETA DIRECTORY SCANNER ACTIVATED! 💀
        🔍 Scanning: {directory}
        📁 Output: {output_dir}
        🔄 Recursive: {recursive}
        🎯 Pattern: {file_pattern}
        ⚡ Threads: {threads}
        🎯 Min Confidence: {min_confidence}
        🔒 Safe Mode: {self.safe_mode}
        🕒 Started: {time.strftime('%Y-%m-%d %H:%M:%S')}
        """)
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Find all files to process
        target_files = self._find_target_files(directory, recursive, file_pattern)
        
        if not target_files:
            print("❌ No files found matching the criteria!")
            return {}
        
        print(f"🎯 Found {len(target_files)} files to process...")
        
        self.stats['start_time'] = time.time()
        self.stats['directories_scanned'] = 1
        self.stats['files_processed'] = 0
        self.stats['total_target_files'] = len(target_files)
        
        # Process files in parallel
        results = self._process_directory_files_parallel(
            target_files, output_path, threads, min_confidence
        )
        
        # Generate directory scanning report
        report = self._generate_directory_report(results, directory, recursive)
        
        return report
    
    def _find_target_files(self, directory: str, recursive: bool, pattern: str) -> List[Path]:
        """Find all files matching criteria in directory"""
        target_files = []
        directory_path = Path(directory)
        
        if not directory_path.exists():
            print(f"❌ Directory doesn't exist: {directory}")
            return []
        
        if recursive:
            # Recursive search with pattern matching
            search_pattern = f"**/{pattern}" if pattern != "*" else "**/*"
            for file_path in directory_path.glob(search_pattern):
                if file_path.is_file():
                    target_files.append(file_path)
        else:
            # Non-recursive search
            for file_path in directory_path.iterdir():
                if file_path.is_file() and fnmatch.fnmatch(file_path.name, pattern):
                    target_files.append(file_path)
        
        # Sort by size (largest first for better progress indication)
        target_files.sort(key=lambda x: x.stat().st_size, reverse=True)
        return target_files
    
    def _process_directory_files_parallel(self, file_paths: List[Path], 
                                        output_dir: Path, threads: int,
                                        min_confidence: float) -> List[Dict]:
        """Process multiple files in parallel with progress tracking"""
        total_files = len(file_paths)
        completed_files = 0
        
        print(f"⚡ Processing {total_files} files with {threads} threads...")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(
                    self._process_single_file, 
                    file_path, output_dir, min_confidence
                ): file_path for file_path in file_paths
            }
            
            results = []
            for future in future_to_file:
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    results.append(result)
                    completed_files += 1
                    
                    # Progress reporting
                    progress = (completed_files / total_files) * 100
                    print(f"📊 Progress: {completed_files}/{total_files} ({progress:.1f}%) - {file_path.name}")
                    
                except Exception as e:
                    print(f"❌ Failed to process {file_path}: {e}")
                    results.append({
                        'file_path': str(file_path),
                        'success': False,
                        'error': str(e),
                        'carved_files': 0
                    })
        
        return results
    
    def _process_single_file(self, file_path: Path, output_dir: Path, 
                           min_confidence: float) -> Dict:
        """Process a single file from directory scan"""
        file_stats = {
            'file_path': str(file_path),
            'file_size': file_path.stat().st_size,
            'success': False,
            'carved_files': 0,
            'carved_bytes': 0,
            'error': None,
            'file_types': defaultdict(int)
        }
        
        try:
            # Create subdirectory for this file's carved content
            file_output_dir = output_dir / f"carved_{file_path.name}_{int(time.time())}"
            file_output_dir.mkdir(parents=True, exist_ok=True)
            
            # Use existing carving logic but for single file
            with open(file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    # Scan the entire file
                    carved_count = self._carve_mapped_file(mm, file_output_dir, min_confidence)
            
            file_stats['success'] = True
            file_stats['carved_files'] = carved_count
            file_stats['carved_bytes'] = sum(f.size for f in self.carved_files[-carved_count:])
            
            # Count file types
            for carved_file in self.carved_files[-carved_count:]:
                file_stats['file_types'][carved_file.file_type] += 1
            
            print(f"✅ {file_path.name}: Carved {carved_count} files")
            
        except Exception as e:
            file_stats['error'] = str(e)
            print(f"❌ {file_path.name}: {e}")
        
        return file_stats
    
    def _carve_mapped_file(self, mm: mmap.mmap, output_dir: Path, 
                          min_confidence: float) -> int:
        """Carve files from memory-mapped file (single file version)"""
        initial_file_count = len(self.carved_files)
        
        for file_type, signatures in self.fucking_quantum_signatures.items():
            for header, footer, _ in signatures:
                if header is None:
                    continue
                
                pos = 0
                while True:
                    pos = mm.find(header, pos)
                    if pos == -1:
                        break
                    
                    end_pos = self._smart_end_detection(mm, pos, file_type, header)
                    
                    if end_pos > pos + len(header):
                        file_data = mm[pos:end_pos]
                        entropy = self._calculate_entropy(file_data)
                        confidence = self._calculate_ml_confidence(file_data, file_type, entropy)
                        
                        if confidence >= min_confidence:
                            file_hash_sha256 = hashlib.sha256(file_data).hexdigest()
                            
                            with self.lock:
                                if file_hash_sha256 not in self.carved_hashes:
                                    self.carved_hashes.add(file_hash_sha256)
                                    
                                    carved_file = CarvedFile(
                                        offset=pos,
                                        size=len(file_data),
                                        file_type=file_type,
                                        signature=header.hex()[:8],
                                        hash_sha256=file_hash_sha256,
                                        hash_md5=hashlib.md5(file_data).hexdigest(),
                                        confidence=confidence,
                                        entropy=entropy,
                                        yara_matches=self._scan_with_yara(file_data),
                                        validated=self._validate_file_header(file_data, file_type)
                                    )
                                    
                                    if not self.safe_mode and confidence > 0.6:
                                        filename = f"{file_type}_{pos:08x}_{confidence:.2f}.{file_type.lower()}"
                                        output_path = output_dir / filename
                                        
                                        if self._safe_file_write(file_data, output_path, file_type):
                                            carved_file.recovered = True
                                            self.stats['files_carved'] += 1
                                            self.stats['bytes_recovered'] += len(file_data)
                                            self.stats['file_types'][file_type] += 1
                                    
                                    self.carved_files.append(carved_file)
                                    self._save_to_database(carved_file)
                    
                    pos += len(header)
        
        return len(self.carved_files) - initial_file_count
    
    def _generate_directory_report(self, results: List[Dict], directory: str, 
                                 recursive: bool) -> Dict:
        """Generate comprehensive directory scanning report"""
        successful_scans = [r for r in results if r['success']]
        failed_scans = [r for r in results if not r['success']]
        
        total_carved = sum(r['carved_files'] for r in successful_scans)
        total_bytes = sum(r['carved_bytes'] for r in successful_scans)
        
        # Aggregate file types across all successful scans
        all_file_types = defaultdict(int)
        for result in successful_scans:
            for file_type, count in result['file_types'].items():
                all_file_types[file_type] += count
        
        report = {
            'metadata': {
                'realm': 'Zeta',
                'commander': 'Alpha',
                'ai': 'Zo',
                'version': '3.1.0',
                'scan_type': 'directory',
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'directory_scanned': directory,
                'recursive': recursive,
                'safe_mode': self.safe_mode
            },
            'statistics': {
                'total_files_processed': len(results),
                'successful_scans': len(successful_scans),
                'failed_scans': len(failed_scans),
                'total_files_carved': total_carved,
                'total_bytes_recovered': total_bytes,
                'scan_duration': time.time() - self.stats['start_time'],
                'file_types': dict(all_file_types)
            },
            'successful_files': [
                {
                    'file_path': r['file_path'],
                    'carved_files': r['carved_files'],
                    'carved_bytes': r['carved_bytes'],
                    'file_types': dict(r['file_types'])
                } for r in successful_scans if r['carved_files'] > 0
            ],
            'failed_files': [
                {
                    'file_path': r['file_path'],
                    'error': r['error']
                } for r in failed_scans
            ]
        }
        
        # Save directory scan report
        report_file = Path(f'zeta_directory_scan_{int(time.time())}.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report

    def scan_and_carve_universal(self, target: str, output_dir: str, 
                               recursive: bool = False, file_pattern: str = "*",
                               threads: int = 8, min_confidence: float = 0.6,
                               deep_scan: bool = False) -> Dict:
        """
        UNIVERSAL SCANNING METHOD - Handles both single files and directories automatically
        """
        target_path = Path(target)
        
        if not target_path.exists():
            print(f"❌ Target doesn't exist: {target}")
            return {}
        
        if target_path.is_file():
            # Single file mode
            print(f"🎯 Single file mode: {target}")
            return self.carve_with_quantum_ml(
                input_file=target,
                output_dir=output_dir,
                threads=threads,
                deep_scan=deep_scan,
                min_confidence=min_confidence
            )
        elif target_path.is_dir():
            # Directory mode
            print(f"📁 Directory mode: {target}")
            return self.scan_directory(
                directory=target,
                output_dir=output_dir,
                recursive=recursive,
                file_pattern=file_pattern,
                threads=threads,
                min_confidence=min_confidence
            )
        else:
            print(f"❌ Unsupported target type: {target}")
            return {}

    def carve_with_quantum_ml(self, input_file: str, output_dir: str, 
                            threads: int = 8, deep_scan: bool = False,
                            min_confidence: float = 0.6) -> Dict:
        """Enhanced carving with ML confidence and safety features"""
        
        # Safety check for device files
        if input_file.startswith('/dev/') and not self.safe_mode:
            print("""
            🚨 WARNING: Direct device access detected!
            For safety, consider using dd first:
            sudo dd if=/dev/sdX of=disk_image.img bs=4M status=progress
            Then run: python zeta_carver.py disk_image.img -o ./recovered
            """)
            if input("Continue anyway? (y/N): ").lower() != 'y':
                return {}
        
        print(f"""
        🚀 ZETA REALM QUANTUM CARVER v3.1 - ENHANCED WITH ML & SAFETY 🔒
        🔧 Input: {input_file}
        📁 Output: {output_dir}
        ⚡ Threads: {threads}
        🔍 Deep Scan: {deep_scan}
        🎯 Min Confidence: {min_confidence}
        🔒 Safe Mode: {self.safe_mode}
        🕒 Started: {time.strftime('%Y-%m-%d %H:%M:%S')}
        """)
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        self.stats['start_time'] = time.time()
        self._create_recovery_session(input_file, output_dir, threads, deep_scan)
        
        # Enhanced parallel carving
        file_size = os.path.getsize(input_file)
        chunk_size = file_size // threads
        
        with open(input_file, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = []
                    
                    for i in range(threads):
                        start = i * chunk_size
                        end = start + chunk_size if i < threads - 1 else file_size
                        
                        future = executor.submit(
                            self._quantum_carve_chunk_enhanced, mm, start, end, i, output_path
                        )
                        futures.append(future)
                    
                    # Collect results
                    for future in futures:
                        chunk_files = future.result()
                        self.carved_files.extend(chunk_files)
        
        # Generate comprehensive report
        report = self._generate_enhanced_report()
        
        print(f"""
        🎉 QUANTUM CARVING COMPLETE!
        📊 Files Carved: {self.stats['files_carved']}
        ✅ Validated: {self.stats['validated_files']}
        🚨 Malware Detected: {self.stats['malware_detected']}
        💾 Bytes Recovered: {self.stats['bytes_recovered']:,}
        ⏱️ Total Time: {time.time() - self.stats['start_time']:.2f}s
        🔒 Safe Mode: {'ACTIVE - no files written' if self.safe_mode else 'INACTIVE'}
        """)
        
        return report
    
    def _create_recovery_session(self, input_file: str, output_dir: str, threads: int, deep_scan: bool):
        """Create recovery session in database"""
        if self.db_conn is None:
            return
            
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO recovery_sessions 
            (timestamp, input_file, output_dir, parameters)
            VALUES (?, ?, ?, ?)
        ''', (time.strftime('%Y-%m-%d %H:%M:%S'), input_file, output_dir,
              json.dumps({'threads': threads, 'deep_scan': deep_scan, 'safe_mode': self.safe_mode})))
        
        self.db_conn.commit()
    
    def _generate_enhanced_report(self) -> Dict:
        """Generate enhanced report with ML metrics"""
        report = {
            'metadata': {
                'realm': 'Zeta',
                'commander': 'Alpha', 
                'ai': 'Zo',
                'version': '3.1.0',
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'safe_mode': self.safe_mode
            },
            'statistics': self.stats.copy(),
            'file_types': dict(self.stats['file_types']),
            'confidence_distribution': self._get_confidence_distribution(),
            'top_files': self._get_top_files_by_confidence(10)
        }
        
        # Save enhanced report
        report_file = Path('zeta_quantum_report.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report
    
    def _get_confidence_distribution(self) -> Dict[str, int]:
        """Get distribution of confidence scores"""
        distribution = defaultdict(int)
        for file in self.carved_files:
            range_key = f"{int(file.confidence * 10) * 10}%-{int(file.confence * 10) * 10 + 10}%"
            distribution[range_key] += 1
        return dict(distribution)
    
    def _get_top_files_by_confidence(self, count: int) -> List[Dict]:
        """Get top files by confidence score"""
        sorted_files = sorted(self.carved_files, key=lambda x: x.confidence, reverse=True)
        return [{
            'offset': f.offset,
            'type': f.file_type,
            'size': f.size,
            'confidence': f.confidence,
            'entropy': f.entropy,
            'validated': f.validated
        } for f in sorted_files[:count]]

# ==================== ENHANCED COMMAND-LINE INTERFACE ====================

def main():
    """Enhanced CLI with directory scanning support"""
    parser = argparse.ArgumentParser(
        description='ZETA REALM QUANTUM CARVER v3.1 - Universal File & Directory Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
UNIVERSAL SCANNING EXAMPLES:
  
  # Single file carving (traditional)
  python zeta_carver_pro.py disk_image.img -o ./recovered

  # Directory scanning (non-recursive)
  python zeta_carver_pro.py /home/user/documents -o ./carved_files --dir-scan

  # Recursive directory scanning with pattern
  python zeta_carver_pro.py /home/user -o ./deep_recovery --dir-scan --recursive --pattern "*.bin"

  # Mixed mode - automatically detects file or directory
  python zeta_carver_pro.py /path/to/target -o ./output --universal

  # Safe directory scanning (preview only)
  python zeta_carver_pro.py /home/user -o ./preview --dir-scan --recursive --safe

DIRECTORY SCANNING OPTIONS:
  --dir-scan : Enable directory scanning mode
  --recursive : Scan subdirectories recursively  
  --pattern : File pattern to match (default: "*")
  --universal : Auto-detect file/directory mode
        """
    )
    
    # Target specification
    target_group = parser.add_argument_group('Target Specification')
    target_group.add_argument('target', nargs='?', help='Target file or directory to scan')
    target_group.add_argument('--input', help='Alternative input file specification')
    
    # Output specification
    target_group.add_argument('-o', '--output', required=True, help='Output directory for carved files')
    
    # Scanning mode
    mode_group = parser.add_argument_group('Scanning Mode')
    mode_group.add_argument('--dir-scan', action='store_true', help='Directory scanning mode')
    mode_group.add_argument('--universal', action='store_true', help='Auto-detect file/directory')
    mode_group.add_argument('--recursive', action='store_true', help='Recursive directory scanning')
    mode_group.add_argument('--pattern', default='*', help='File pattern for directory scanning')
    
    # Processing options
    processing_group = parser.add_argument_group('Processing Options')
    processing_group.add_argument('-t', '--threads', type=int, default=8, help='Processing threads')
    processing_group.add_argument('--deep', action='store_true', help='Deep scanning mode')
    processing_group.add_argument('--min-confidence', type=float, default=0.6, help='Minimum confidence score')
    
    # Safety options
    safety_group = parser.add_argument_group('Safety Options')
    safety_group.add_argument('--safe', action='store_true', help='Safe mode (preview, no file writing)')
    safety_group.add_argument('--yara', action='store_true', help='Enable YARA malware scanning')
    
    args = parser.parse_args()
    
    # Determine target
    target = args.target or args.input
    if not target:
        print("❌ No target specified! Use --help for usage information.")
        return
    
    if not os.path.exists(target):
        print(f"❌ Target doesn't exist: {target}")
        return
    
    # Initialize carver
    carver = QuantumZetaCarverPro(safe_mode=args.safe)
    
    try:
        # Determine scanning mode
        if args.universal:
            # Universal auto-detection mode
            report = carver.scan_and_carve_universal(
                target=target,
                output_dir=args.output,
                recursive=args.recursive,
                file_pattern=args.pattern,
                threads=args.threads,
                min_confidence=args.min_confidence,
                deep_scan=args.deep
            )
        elif args.dir_scan or os.path.isdir(target):
            # Directory scanning mode
            report = carver.scan_directory(
                directory=target,
                output_dir=args.output,
                recursive=args.recursive,
                file_pattern=args.pattern,
                threads=args.threads,
                min_confidence=args.min_confidence
            )
        else:
            # Single file mode (traditional)
            report = carver.carve_with_quantum_ml(
                input_file=target,
                output_dir=args.output,
                threads=args.threads,
                deep_scan=args.deep,
                min_confidence=args.min_confidence
            )
        
        # Report generation
        if report:
            print(f"📊 Scan report generated with {report['statistics'].get('total_files_carved', 0)} files carved")
            
            if args.safe:
                print("🔒 SAFE MODE: No files were written. Disable --safe to actually recover files.")
            else:
                print("🎯 MISSION ACCOMPLISHED, ALPHA! FILES RESURRECTED! 💪")
        
    except KeyboardInterrupt:
        print("\n⚠️ Scanning interrupted by user!")
    except Exception as e:
        print(f"💥 QUANTUM FAILURE: {e}")
        if carver.db_conn:
            carver.db_conn.close()

def demonstrate_directory_scanning():
    """Demonstrate the new directory scanning capabilities"""
    
    carver = QuantumZetaCarverPro(safe_mode=True)  # Safe mode for demonstration
    
    examples = [
        # Single file (traditional)
        {
            'target': 'disk_image.img',
            'output': './recovered_single',
            'description': 'Traditional single file carving'
        },
        # Directory non-recursive
        {
            'target': '/home/user/documents',
            'output': './recovered_docs',
            'recursive': False,
            'pattern': '*.pdf',
            'description': 'Non-recursive PDF scanning in documents folder'
        },
        # Directory recursive  
        {
            'target': '/home/user',
            'output': './deep_recovery',
            'recursive': True,
            'pattern': '*.jpg',
            'description': 'Recursive JPEG recovery from entire home directory'
        },
        # Universal mode
        {
            'target': '/unknown/path',  # Could be file or directory
            'output': './universal_output',
            'universal': True,
            'description': 'Universal auto-detection mode'
        }
    ]
    
    print("""
    🚀 ZETA DIRECTORY SCANNING CAPABILITIES DEMONSTRATED! 💀
    
    NEW FEATURES:
    📁 Recursive directory scanning
    🎯 File pattern matching
    ⚡ Parallel file processing
    🔄 Universal auto-detection mode
    📊 Comprehensive directory reports
    """)

if __name__ == "__main__":
    main()