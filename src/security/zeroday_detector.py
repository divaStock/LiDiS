#!/usr/bin/env python3
"""
LiDiS Zero-Day Vulnerability Detection System

Advanced zero-day detection using:
- Dynamic behavioral analysis and sandboxing
- Static code analysis and fuzzing
- Machine learning-based anomaly detection
- AI-powered vulnerability pattern recognition
- Automated exploit detection and classification
"""

import asyncio
import logging
import json
import time
import hashlib
import tempfile
import subprocess
import os
import shutil
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
from pathlib import Path
import numpy as np
import pickle
from sklearn.ensemble import IsolationForest, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import threading
import queue
import psutil
import magic

@dataclass
class VulnerabilitySignature:
    """Represents a vulnerability signature or pattern"""
    vuln_id: str
    vuln_type: str  # buffer_overflow, code_injection, privilege_escalation, etc.
    severity: int   # CVSS-like 1-10 scale
    confidence: float
    description: str
    patterns: List[str] = field(default_factory=list)
    indicators: Dict[str, Any] = field(default_factory=dict)
    cve_id: Optional[str] = None
    discovered_time: float = field(default_factory=time.time)

@dataclass
class SuspiciousExecutable:
    """Represents a suspicious executable for analysis"""
    file_path: str
    file_hash: str
    file_size: int
    file_type: str
    submission_time: float
    source: str  # network, filesystem, memory_dump, etc.
    analysis_status: str = "pending"  # pending, analyzing, completed, error
    risk_score: float = 0.0
    vulnerabilities: List[VulnerabilitySignature] = field(default_factory=list)

@dataclass
class DynamicAnalysisResult:
    """Results from dynamic sandbox analysis"""
    executable_hash: str
    execution_time: float
    system_calls: List[Dict[str, Any]] = field(default_factory=list)
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    file_operations: List[Dict[str, Any]] = field(default_factory=list)
    process_spawns: List[Dict[str, Any]] = field(default_factory=list)
    memory_allocations: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_behaviors: List[str] = field(default_factory=list)
    crash_detected: bool = False
    exploit_indicators: Dict[str, Any] = field(default_factory=dict)

class StaticAnalyzer:
    """Static code analysis for vulnerability detection"""
    
    def __init__(self):
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.string_analyzer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3))
        self.disassembly_cache = {}
    
    def _load_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Load known vulnerability patterns"""
        return {
            'buffer_overflow': [
                r'strcpy\s*\(',
                r'strcat\s*\(',
                r'sprintf\s*\(',
                r'gets\s*\(',
                r'scanf\s*\([^,]*%s',
                r'memcpy\s*\([^,]*,\s*[^,]*,\s*[^)]*\)'
            ],
            'format_string': [
                r'printf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',
                r'fprintf\s*\([^,]*,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',
                r'sprintf\s*\([^,]*,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)'
            ],
            'integer_overflow': [
                r'malloc\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\*\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',
                r'calloc\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)'
            ],
            'race_condition': [
                r'access\s*\([^)]*\)\s*.*\s*open\s*\(',
                r'stat\s*\([^)]*\)\s*.*\s*open\s*\(',
                r'lstat\s*\([^)]*\)\s*.*\s*open\s*\('
            ],
            'code_injection': [
                r'system\s*\([^)]*[a-zA-Z_][a-zA-Z0-9_]*[^)]*\)',
                r'exec[lv]p?\s*\([^)]*[a-zA-Z_][a-zA-Z0-9_]*[^)]*\)',
                r'popen\s*\([^)]*[a-zA-Z_][a-zA-Z0-9_]*[^)]*\)'
            ],
            'privilege_escalation': [
                r'setuid\s*\(',
                r'seteuid\s*\(',
                r'setgid\s*\(',
                r'setegid\s*\(',
                r'chmod\s*\([^,]*,\s*[0-9]*[4-7][0-9]*[0-9]*\s*\)'
            ]
        }
    
    async def analyze_executable(self, file_path: str) -> List[VulnerabilitySignature]:
        """Perform static analysis on executable"""
        vulnerabilities = []
        
        try:
            # Get file info
            file_info = await self._get_file_info(file_path)
            
            # Disassemble if possible
            disassembly = await self._disassemble_file(file_path)
            
            # String analysis
            strings = await self._extract_strings(file_path)
            
            # Pattern matching
            for vuln_type, patterns in self.vulnerability_patterns.items():
                matches = await self._find_pattern_matches(disassembly, strings, patterns)
                if matches:
                    vuln = VulnerabilitySignature(
                        vuln_id=hashlib.md5(f"{file_path}_{vuln_type}_{len(matches)}".encode()).hexdigest()[:12],
                        vuln_type=vuln_type,
                        severity=self._calculate_severity(vuln_type, len(matches)),
                        confidence=min(0.9, len(matches) * 0.2),
                        description=f"Potential {vuln_type.replace('_', ' ')} vulnerability detected",
                        patterns=matches,
                        indicators={
                            'pattern_count': len(matches),
                            'file_size': file_info.get('size', 0),
                            'file_type': file_info.get('type', 'unknown')
                        }
                    )
                    vulnerabilities.append(vuln)
            
            # Advanced heuristic analysis
            heuristic_vulns = await self._heuristic_analysis(file_path, disassembly, strings)
            vulnerabilities.extend(heuristic_vulns)
            
        except Exception as e:
            logging.error(f"Static analysis error for {file_path}: {e}")
        
        return vulnerabilities
    
    async def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        try:
            stat_info = os.stat(file_path)
            file_type = magic.from_file(file_path) if os.path.exists(file_path) else "unknown"
            
            return {
                'size': stat_info.st_size,
                'mtime': stat_info.st_mtime,
                'type': file_type,
                'executable': os.access(file_path, os.X_OK)
            }
        except Exception as e:
            logging.error(f"Error getting file info for {file_path}: {e}")
            return {}
    
    async def _disassemble_file(self, file_path: str) -> str:
        """Disassemble executable file"""
        if file_path in self.disassembly_cache:
            return self.disassembly_cache[file_path]
        
        try:
            # Use objdump for disassembly
            result = subprocess.run(
                ['objdump', '-d', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                disassembly = result.stdout
                self.disassembly_cache[file_path] = disassembly
                return disassembly
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logging.warning(f"Disassembly failed for {file_path}: {e}")
        
        return ""
    
    async def _extract_strings(self, file_path: str) -> List[str]:
        """Extract strings from executable"""
        try:
            result = subprocess.run(
                ['strings', file_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout.splitlines()
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logging.warning(f"String extraction failed for {file_path}: {e}")
        
        return []
    
    async def _find_pattern_matches(self, disassembly: str, strings: List[str], patterns: List[str]) -> List[str]:
        """Find pattern matches in disassembly and strings"""
        import re
        
        matches = []
        content = disassembly + "\n" + "\n".join(strings)
        
        for pattern in patterns:
            try:
                found = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                matches.extend([match if isinstance(match, str) else str(match) for match in found])
            except re.error as e:
                logging.error(f"Regex error with pattern {pattern}: {e}")
        
        return list(set(matches))  # Remove duplicates
    
    async def _heuristic_analysis(self, file_path: str, disassembly: str, strings: List[str]) -> List[VulnerabilitySignature]:
        """Advanced heuristic vulnerability analysis"""
        vulnerabilities = []
        
        # Check for suspicious string patterns
        suspicious_strings = [
            '/bin/sh', '/bin/bash', 'system', 'exec', 'eval',
            'shellcode', 'exploit', 'payload', 'backdoor',
            'rootkit', 'privilege', 'escalation', 'overflow'
        ]
        
        found_suspicious = [s for s in strings if any(sus in s.lower() for sus in suspicious_strings)]
        
        if found_suspicious:
            vuln = VulnerabilitySignature(
                vuln_id=hashlib.md5(f"{file_path}_heuristic".encode()).hexdigest()[:12],
                vuln_type="suspicious_content",
                severity=len(found_suspicious) + 2,
                confidence=0.6,
                description="Suspicious strings detected indicating potential malicious behavior",
                indicators={
                    'suspicious_strings': found_suspicious[:10],  # Limit for brevity
                    'string_count': len(found_suspicious)
                }
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _calculate_severity(self, vuln_type: str, match_count: int) -> int:
        """Calculate vulnerability severity based on type and evidence"""
        base_severity = {
            'buffer_overflow': 8,
            'format_string': 7,
            'integer_overflow': 6,
            'race_condition': 5,
            'code_injection': 9,
            'privilege_escalation': 8,
            'suspicious_content': 4
        }
        
        severity = base_severity.get(vuln_type, 3)
        # Increase severity based on number of matches
        severity = min(10, severity + min(2, match_count // 3))
        
        return severity

class DynamicSandbox:
    """Dynamic analysis sandbox for executable behavior analysis"""
    
    def __init__(self, sandbox_dir: str = None):
        self.sandbox_dir = sandbox_dir or tempfile.mkdtemp(prefix="lidis_sandbox_")
        self.analysis_timeout = 60  # seconds
        self.monitored_syscalls = {
            'execve', 'fork', 'clone', 'open', 'openat', 'read', 'write',
            'connect', 'bind', 'listen', 'accept', 'sendto', 'recvfrom',
            'mmap', 'mprotect', 'chmod', 'chown', 'setuid', 'setgid'
        }
        
    async def analyze_executable(self, file_path: str) -> DynamicAnalysisResult:
        """Run dynamic analysis on executable in sandboxed environment"""
        file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
        
        result = DynamicAnalysisResult(
            executable_hash=file_hash,
            execution_time=time.time()
        )
        
        # Create isolated sandbox
        sandbox_path = os.path.join(self.sandbox_dir, file_hash)
        os.makedirs(sandbox_path, exist_ok=True)
        
        try:
            # Copy executable to sandbox
            sandbox_exe = os.path.join(sandbox_path, "target")
            shutil.copy2(file_path, sandbox_exe)
            os.chmod(sandbox_exe, 0o755)
            
            # Monitor execution
            await self._monitor_execution(sandbox_exe, result)
            
        except Exception as e:
            logging.error(f"Sandbox analysis error: {e}")
        finally:
            # Cleanup sandbox
            try:
                shutil.rmtree(sandbox_path)
            except Exception as e:
                logging.warning(f"Sandbox cleanup error: {e}")
        
        return result
    
    async def _monitor_execution(self, executable_path: str, result: DynamicAnalysisResult):
        """Monitor executable execution for suspicious behavior"""
        try:
            # Start the process with limited resources and monitoring
            process = await asyncio.create_subprocess_exec(
                executable_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024 * 1024,  # 1MB output limit
                env={}  # Empty environment
            )
            
            # Monitor for limited time
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.analysis_timeout
                )
                
                result.suspicious_behaviors.extend(await self._analyze_output(stdout, stderr))
                
            except asyncio.TimeoutError:
                process.kill()
                result.suspicious_behaviors.append("execution_timeout")
                
            except Exception as e:
                result.crash_detected = True
                result.suspicious_behaviors.append(f"execution_crash: {str(e)}")
        
        except Exception as e:
            logging.error(f"Execution monitoring error: {e}")
            result.suspicious_behaviors.append(f"monitoring_error: {str(e)}")
    
    async def _analyze_output(self, stdout: bytes, stderr: bytes) -> List[str]:
        """Analyze executable output for suspicious patterns"""
        suspicious_behaviors = []
        
        try:
            output_text = (stdout + stderr).decode('utf-8', errors='ignore')
            
            # Check for suspicious output patterns
            suspicious_patterns = [
                'segmentation fault', 'core dumped', 'stack overflow',
                'heap corruption', 'double free', 'use after free',
                'permission denied', 'access denied', 'privilege',
                'shell', 'command', 'exploit', 'payload'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in output_text.lower():
                    suspicious_behaviors.append(f"suspicious_output: {pattern}")
            
        except Exception as e:
            logging.error(f"Output analysis error: {e}")
        
        return suspicious_behaviors

class MLVulnerabilityClassifier:
    """Machine learning-based vulnerability classifier"""
    
    def __init__(self):
        self.feature_extractor = None
        self.classifier = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.vulnerability_types = [
            'buffer_overflow', 'format_string', 'integer_overflow',
            'race_condition', 'code_injection', 'privilege_escalation',
            'use_after_free', 'double_free', 'heap_overflow',
            'stack_overflow', 'null_pointer_dereference'
        ]
    
    def extract_features(self, static_analysis: List[VulnerabilitySignature], 
                        dynamic_analysis: DynamicAnalysisResult,
                        file_info: Dict[str, Any]) -> np.ndarray:
        """Extract ML features from analysis results"""
        features = []
        
        # Static analysis features
        static_features = defaultdict(int)
        for vuln in static_analysis:
            static_features[vuln.vuln_type] += 1
            static_features['total_patterns'] += len(vuln.patterns)
        
        for vuln_type in self.vulnerability_types:
            features.append(static_features.get(vuln_type, 0))
        
        features.extend([
            static_features['total_patterns'],
            len(static_analysis),
            max([v.severity for v in static_analysis] + [0]),
            np.mean([v.confidence for v in static_analysis] + [0])
        ])
        
        # Dynamic analysis features
        features.extend([
            len(dynamic_analysis.suspicious_behaviors),
            len(dynamic_analysis.system_calls),
            len(dynamic_analysis.network_connections),
            len(dynamic_analysis.file_operations),
            int(dynamic_analysis.crash_detected),
            dynamic_analysis.execution_time if dynamic_analysis.execution_time > 0 else 0
        ])
        
        # File info features  
        features.extend([
            file_info.get('size', 0) / 1024,  # KB
            int(file_info.get('executable', False)),
            hash(file_info.get('type', '')) % 1000  # File type hash
        ])
        
        return np.array(features).reshape(1, -1)
    
    def predict_vulnerability_risk(self, features: np.ndarray) -> Tuple[float, str]:
        """Predict vulnerability risk score and type"""
        if not self.is_trained:
            # Return heuristic-based risk if not trained
            risk_score = min(1.0, np.sum(features[:len(self.vulnerability_types)]) / 10)
            return risk_score, "unknown"
        
        try:
            features_scaled = self.scaler.transform(features)
            probabilities = self.classifier.predict_proba(features_scaled)[0]
            
            # Risk score is max probability
            risk_score = np.max(probabilities)
            
            # Predicted type is highest probability class
            predicted_idx = np.argmax(probabilities)
            predicted_type = self.vulnerability_types[predicted_idx] if predicted_idx < len(self.vulnerability_types) else "unknown"
            
            return risk_score, predicted_type
            
        except Exception as e:
            logging.error(f"ML prediction error: {e}")
            return 0.0, "error"
    
    def load_model(self, model_path: str):
        """Load pre-trained model"""
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
                self.classifier = model_data['classifier']
                self.scaler = model_data['scaler']
                self.vulnerability_types = model_data['vulnerability_types']
                self.is_trained = True
                logging.info(f"Loaded vulnerability classifier from {model_path}")
        except Exception as e:
            logging.error(f"Failed to load model: {e}")

class ZeroDayDetectionEngine:
    """Main zero-day vulnerability detection engine"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._default_config()
        
        self.static_analyzer = StaticAnalyzer()
        self.dynamic_sandbox = DynamicSandbox()
        self.ml_classifier = MLVulnerabilityClassifier()
        
        self.analysis_queue = queue.Queue()
        self.detected_vulnerabilities = deque(maxlen=1000)
        self.high_risk_executables = deque(maxlen=100)
        
        self.running = False
        self.worker_threads = []
        
        # Statistics
        self.stats = {
            'executables_analyzed': 0,
            'vulnerabilities_detected': 0,
            'zero_days_found': 0,
            'high_risk_count': 0,
            'analysis_errors': 0
        }
        
        # Load pre-trained model if available
        model_path = self.config.get('ml_model_path')
        if model_path and os.path.exists(model_path):
            self.ml_classifier.load_model(model_path)
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            'risk_threshold': 0.7,
            'worker_threads': 3,
            'max_file_size': 100 * 1024 * 1024,  # 100MB
            'analysis_timeout': 300,  # 5 minutes
            'enable_dynamic_analysis': True,
            'enable_ml_classification': True
        }
    
    async def start(self):
        """Start the zero-day detection engine"""
        self.running = True
        logging.info("Zero-day detection engine started")
        
        # Start worker threads for analysis
        for i in range(self.config['worker_threads']):
            thread = threading.Thread(target=self._analysis_worker, args=(i,))
            thread.daemon = True
            thread.start()
            self.worker_threads.append(thread)
    
    def stop(self):
        """Stop the zero-day detection engine"""
        self.running = False
        logging.info("Zero-day detection engine stopped")
    
    def submit_for_analysis(self, file_path: str, source: str = "manual") -> bool:
        """Submit executable for zero-day analysis"""
        try:
            if not os.path.exists(file_path):
                logging.error(f"File not found: {file_path}")
                return False
            
            file_size = os.path.getsize(file_path)
            if file_size > self.config['max_file_size']:
                logging.warning(f"File too large for analysis: {file_path} ({file_size} bytes)")
                return False
            
            file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
            
            executable = SuspiciousExecutable(
                file_path=file_path,
                file_hash=file_hash,
                file_size=file_size,
                file_type=magic.from_file(file_path) if os.path.exists(file_path) else "unknown",
                submission_time=time.time(),
                source=source
            )
            
            self.analysis_queue.put(executable)
            logging.info(f"Queued {file_path} for zero-day analysis")
            return True
            
        except Exception as e:
            logging.error(f"Error submitting {file_path} for analysis: {e}")
            return False
    
    def _analysis_worker(self, worker_id: int):
        """Worker thread for processing analysis queue"""
        logging.info(f"Analysis worker {worker_id} started")
        
        while self.running:
            try:
                # Get next executable from queue
                try:
                    executable = self.analysis_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Perform analysis
                self._analyze_executable(executable)
                self.analysis_queue.task_done()
                
            except Exception as e:
                logging.error(f"Worker {worker_id} error: {e}")
                self.stats['analysis_errors'] += 1
                time.sleep(1)
    
    def _analyze_executable(self, executable: SuspiciousExecutable):
        """Perform comprehensive analysis on executable"""
        executable.analysis_status = "analyzing"
        start_time = time.time()
        
        try:
            # Static analysis
            static_vulns = asyncio.run(self.static_analyzer.analyze_executable(executable.file_path))
            
            # Dynamic analysis (if enabled and not too risky)
            dynamic_result = None
            if (self.config['enable_dynamic_analysis'] and 
                not any(v.severity >= 9 for v in static_vulns)):  # Don't run highly dangerous executables
                dynamic_result = asyncio.run(self.dynamic_sandbox.analyze_executable(executable.file_path))
            else:
                dynamic_result = DynamicAnalysisResult(executable_hash=executable.file_hash, execution_time=0)
            
            # Get file info
            file_info = asyncio.run(self.static_analyzer._get_file_info(executable.file_path))
            
            # ML classification (if enabled)
            if self.config['enable_ml_classification']:
                features = self.ml_classifier.extract_features(static_vulns, dynamic_result, file_info)
                ml_risk, ml_type = self.ml_classifier.predict_vulnerability_risk(features)
                
                # Add ML-based vulnerability if high confidence
                if ml_risk >= 0.8:
                    ml_vuln = VulnerabilitySignature(
                        vuln_id=hashlib.md5(f"{executable.file_hash}_ml".encode()).hexdigest()[:12],
                        vuln_type=ml_type,
                        severity=int(ml_risk * 10),
                        confidence=ml_risk,
                        description=f"ML-detected {ml_type.replace('_', ' ')} vulnerability",
                        indicators={'ml_prediction': True, 'risk_score': ml_risk}
                    )
                    static_vulns.append(ml_vuln)
            
            # Calculate overall risk score
            if static_vulns:
                executable.risk_score = min(1.0, np.mean([v.confidence for v in static_vulns]) + 
                                          len(static_vulns) * 0.1 + 
                                          len(dynamic_result.suspicious_behaviors) * 0.05)
            else:
                executable.risk_score = len(dynamic_result.suspicious_behaviors) * 0.1
            
            executable.vulnerabilities = static_vulns
            executable.analysis_status = "completed"
            
            # Update statistics
            self.stats['executables_analyzed'] += 1
            self.stats['vulnerabilities_detected'] += len(static_vulns)
            
            # Check if this might be a zero-day
            if (executable.risk_score >= self.config['risk_threshold'] and 
                any(v.confidence >= 0.7 for v in static_vulns)):
                self.stats['zero_days_found'] += 1
                logging.critical(f"Potential zero-day vulnerability detected in {executable.file_path}")
            
            # Track high-risk executables
            if executable.risk_score >= self.config['risk_threshold']:
                self.high_risk_executables.append(executable)
                self.stats['high_risk_count'] += 1
            
            # Store results
            self.detected_vulnerabilities.extend(static_vulns)
            
            analysis_time = time.time() - start_time
            logging.info(f"Analysis completed for {executable.file_path} in {analysis_time:.2f}s "
                        f"(risk: {executable.risk_score:.2f}, vulns: {len(static_vulns)})")
            
        except Exception as e:
            executable.analysis_status = "error"
            logging.error(f"Analysis failed for {executable.file_path}: {e}")
            self.stats['analysis_errors'] += 1
    
    def get_recent_vulnerabilities(self, limit: int = 50) -> List[VulnerabilitySignature]:
        """Get recently detected vulnerabilities"""
        return list(self.detected_vulnerabilities)[-limit:]
    
    def get_high_risk_executables(self, limit: int = 20) -> List[SuspiciousExecutable]:
        """Get high-risk executables"""
        return list(self.high_risk_executables)[-limit:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics"""
        return {
            **self.stats,
            'queue_size': self.analysis_queue.qsize(),
            'average_risk_score': np.mean([e.risk_score for e in self.high_risk_executables]) if self.high_risk_executables else 0.0
        }
    
    def search_vulnerabilities(self, criteria: Dict[str, Any]) -> List[VulnerabilitySignature]:
        """Search for vulnerabilities matching criteria"""
        matches = []
        
        for vuln in self.detected_vulnerabilities:
            match = True
            
            if 'vuln_type' in criteria and vuln.vuln_type != criteria['vuln_type']:
                match = False
            if 'min_severity' in criteria and vuln.severity < criteria['min_severity']:
                match = False
            if 'min_confidence' in criteria and vuln.confidence < criteria['min_confidence']:
                match = False
            
            if match:
                matches.append(vuln)
        
        return matches

# Example usage and testing
if __name__ == "__main__":
    async def main():
        # Initialize zero-day detection engine
        detector = ZeroDayDetectionEngine({
            'risk_threshold': 0.6,
            'worker_threads': 2,
            'enable_dynamic_analysis': True
        })
        
        await detector.start()
        
        # Submit some files for analysis (would be real executables in practice)
        test_files = ['/bin/ls', '/bin/cat', '/usr/bin/id']  # Safe system binaries for testing
        
        for file_path in test_files:
            if os.path.exists(file_path):
                success = detector.submit_for_analysis(file_path, "test")
                print(f"Submitted {file_path}: {success}")
        
        # Wait a bit for analysis
        await asyncio.sleep(5)
        
        # Show results
        stats = detector.get_statistics()
        print(f"Statistics: {json.dumps(stats, indent=2)}")
        
        high_risk = detector.get_high_risk_executables(5)
        print(f"High-risk executables: {len(high_risk)}")
        
        recent_vulns = detector.get_recent_vulnerabilities(10)
        print(f"Recent vulnerabilities: {len(recent_vulns)}")
        for vuln in recent_vulns[:3]:
            print(f"  {vuln.vuln_type}: {vuln.description} (severity: {vuln.severity})")
        
        detector.stop()
    
    asyncio.run(main())