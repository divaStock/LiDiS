#!/usr/bin/env python3
"""
LiDiS TTP Detection System
MITRE ATT&CK Framework-based Tactics, Techniques, and Procedures Detection

This module implements comprehensive TTP detection capabilities:
- MITRE ATT&CK technique mapping and detection
- Behavioral analysis for attack chain identification
- Real-time threat hunting automation
- Attack pattern correlation and timeline reconstruction
"""

import asyncio
import logging
import json
import time
import re
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict, field
from collections import defaultdict, deque
from enum import Enum
import subprocess
import psutil
import os
from datetime import datetime, timedelta

class AttackTactic(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"

@dataclass
class TTPEvent:
    """Represents a detected TTP event"""
    timestamp: float
    technique_id: str
    technique_name: str
    tactic: AttackTactic
    severity: int  # 1-10 scale
    confidence: float  # 0.0-1.0
    source_process: Optional[str] = None
    source_user: Optional[str] = None
    source_ip: Optional[str] = None
    target_system: Optional[str] = None
    indicators: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    mitigated: bool = False

@dataclass
class AttackChain:
    """Represents a detected attack chain/campaign"""
    chain_id: str
    start_time: float
    last_activity: float
    tactics_seen: Set[AttackTactic] = field(default_factory=set)
    techniques_used: List[str] = field(default_factory=list)
    events: List[TTPEvent] = field(default_factory=list)
    attacker_ip: Optional[str] = None
    target_systems: Set[str] = field(default_factory=set)
    severity: int = 1
    active: bool = True

class MITRETechniqueDB:
    """MITRE ATT&CK technique database and detection rules"""
    
    def __init__(self):
        self.techniques = self._load_techniques()
        self.detection_rules = self._load_detection_rules()
    
    def _load_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Load MITRE ATT&CK techniques (simplified subset for demo)"""
        return {
            # Initial Access
            "T1566.001": {
                "name": "Spearphishing Attachment",
                "tactic": AttackTactic.INITIAL_ACCESS,
                "description": "Adversaries may send spearphishing emails with malicious attachments",
                "platforms": ["Windows", "macOS", "Linux"],
                "data_sources": ["Email Gateway", "File Monitoring", "Process Monitoring"]
            },
            "T1190": {
                "name": "Exploit Public-Facing Application", 
                "tactic": AttackTactic.INITIAL_ACCESS,
                "description": "Adversaries may attempt to exploit vulnerabilities in internet-facing applications",
                "platforms": ["Windows", "Linux", "macOS", "Network"],
                "data_sources": ["Application Logs", "Network Traffic"]
            },
            
            # Execution
            "T1059.001": {
                "name": "PowerShell",
                "tactic": AttackTactic.EXECUTION,
                "description": "Adversaries may abuse PowerShell commands and scripts for execution",
                "platforms": ["Windows"],
                "data_sources": ["PowerShell Logs", "Process Monitoring"]
            },
            "T1059.004": {
                "name": "Unix Shell",
                "tactic": AttackTactic.EXECUTION,
                "description": "Adversaries may abuse Unix shell commands and scripts for execution", 
                "platforms": ["Linux", "macOS"],
                "data_sources": ["Command History", "Process Monitoring"]
            },
            
            # Persistence
            "T1053.003": {
                "name": "Cron",
                "tactic": AttackTactic.PERSISTENCE,
                "description": "Adversaries may abuse the cron utility for task scheduling for persistence",
                "platforms": ["Linux", "macOS"],
                "data_sources": ["File Monitoring", "Process Monitoring"]
            },
            "T1574.001": {
                "name": "DLL Search Order Hijacking",
                "tactic": AttackTactic.PERSISTENCE,
                "description": "Adversaries may execute malicious payloads by hijacking DLL search order",
                "platforms": ["Windows"],
                "data_sources": ["DLL Monitoring", "Process Monitoring"]
            },
            
            # Privilege Escalation
            "T1548.003": {
                "name": "Sudo and Sudo Caching",
                "tactic": AttackTactic.PRIVILEGE_ESCALATION,
                "description": "Adversaries may perform sudo caching and/or use sudo to escalate privileges",
                "platforms": ["Linux", "macOS"],
                "data_sources": ["Command History", "Process Monitoring"]
            },
            
            # Defense Evasion
            "T1070.004": {
                "name": "File Deletion",
                "tactic": AttackTactic.DEFENSE_EVASION,
                "description": "Adversaries may delete files left behind by tools or actions",
                "platforms": ["Linux", "macOS", "Windows"],
                "data_sources": ["File Monitoring", "Process Monitoring"]
            },
            "T1036.005": {
                "name": "Match Legitimate Name or Location",
                "tactic": AttackTactic.DEFENSE_EVASION,
                "description": "Adversaries may match legitimate file names and locations",
                "platforms": ["Linux", "macOS", "Windows"],
                "data_sources": ["File Monitoring", "Process Monitoring"]
            },
            
            # Credential Access
            "T1003.008": {
                "name": "/etc/passwd and /etc/shadow",
                "tactic": AttackTactic.CREDENTIAL_ACCESS,
                "description": "Adversaries may attempt to dump credentials from /etc/passwd and /etc/shadow",
                "platforms": ["Linux"],
                "data_sources": ["File Monitoring", "Command History"]
            },
            
            # Discovery
            "T1057": {
                "name": "Process Discovery",
                "tactic": AttackTactic.DISCOVERY,
                "description": "Adversaries may attempt to get information about running processes",
                "platforms": ["Linux", "macOS", "Windows"],
                "data_sources": ["Process Monitoring", "Command History"]
            },
            "T1082": {
                "name": "System Information Discovery",
                "tactic": AttackTactic.DISCOVERY,
                "description": "An adversary may attempt to get detailed information about the OS and hardware",
                "platforms": ["Linux", "macOS", "Windows"],
                "data_sources": ["Process Monitoring", "Command History"]
            },
            
            # Lateral Movement
            "T1021.004": {
                "name": "SSH",
                "tactic": AttackTactic.LATERAL_MOVEMENT,
                "description": "Adversaries may use SSH to laterally move within a network",
                "platforms": ["Linux", "macOS"],
                "data_sources": ["Authentication Logs", "Network Traffic"]
            },
            
            # Command and Control
            "T1071.001": {
                "name": "Web Protocols",
                "tactic": AttackTactic.COMMAND_AND_CONTROL,
                "description": "Adversaries may communicate using application layer web protocols",
                "platforms": ["Linux", "macOS", "Windows"],
                "data_sources": ["Network Traffic", "Proxy Logs"]
            },
            
            # Exfiltration
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "tactic": AttackTactic.EXFILTRATION,
                "description": "Adversaries may steal data by exfiltrating it over existing C2 channel",
                "platforms": ["Linux", "macOS", "Windows"],
                "data_sources": ["Network Traffic", "Process Monitoring"]
            }
        }
    
    def _load_detection_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load detection rules for each technique"""
        return {
            "T1059.004": [  # Unix Shell
                {
                    "rule_type": "command_pattern",
                    "pattern": r"(curl|wget).*\|(sh|bash|zsh)",
                    "confidence": 0.8,
                    "description": "Download and execute script pattern"
                },
                {
                    "rule_type": "command_pattern", 
                    "pattern": r"echo\s+.*\|\s*base64\s+-d\s*\|\s*(sh|bash)",
                    "confidence": 0.9,
                    "description": "Base64 encoded command execution"
                }
            ],
            "T1053.003": [  # Cron
                {
                    "rule_type": "file_modification",
                    "path": "/var/spool/cron/crontabs/*",
                    "confidence": 0.7,
                    "description": "Crontab file modification"
                },
                {
                    "rule_type": "command_pattern",
                    "pattern": r"crontab\s+-e",
                    "confidence": 0.6,
                    "description": "Crontab editing command"
                }
            ],
            "T1548.003": [  # Sudo and Sudo Caching
                {
                    "rule_type": "command_pattern",
                    "pattern": r"sudo\s+.*",
                    "confidence": 0.3,
                    "description": "Sudo command usage"
                },
                {
                    "rule_type": "auth_logs",
                    "pattern": r"sudo.*COMMAND=.*",
                    "confidence": 0.5,
                    "description": "Sudo command in auth logs"
                }
            ],
            "T1003.008": [  # /etc/passwd and /etc/shadow
                {
                    "rule_type": "file_access",
                    "path": "/etc/shadow",
                    "confidence": 0.9,
                    "description": "Shadow file access"
                },
                {
                    "rule_type": "command_pattern",
                    "pattern": r"cat\s+(/etc/passwd|/etc/shadow)",
                    "confidence": 0.8,
                    "description": "Password file enumeration"
                }
            ],
            "T1057": [  # Process Discovery
                {
                    "rule_type": "command_pattern",
                    "pattern": r"ps\s+(aux|ef|-ef)",
                    "confidence": 0.4,
                    "description": "Process listing command"
                }
            ],
            "T1082": [  # System Information Discovery
                {
                    "rule_type": "command_pattern",
                    "pattern": r"(uname|whoami|id|groups|cat /etc/os-release)",
                    "confidence": 0.4,
                    "description": "System information gathering"
                }
            ],
            "T1021.004": [  # SSH
                {
                    "rule_type": "auth_logs",
                    "pattern": r"sshd.*Accepted.*",
                    "confidence": 0.3,
                    "description": "SSH authentication success"
                },
                {
                    "rule_type": "network_connection",
                    "port": 22,
                    "confidence": 0.2,
                    "description": "SSH connection"
                }
            ]
        }
    
    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get technique information by ID"""
        return self.techniques.get(technique_id)
    
    def get_detection_rules(self, technique_id: str) -> List[Dict[str, Any]]:
        """Get detection rules for a technique"""
        return self.detection_rules.get(technique_id, [])

class ProcessMonitor:
    """Monitor system processes for TTP indicators"""
    
    def __init__(self):
        self.monitored_processes = {}
        self.command_history = deque(maxlen=1000)
        
    async def start_monitoring(self):
        """Start process monitoring"""
        while True:
            try:
                current_processes = {p.pid: p for p in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time'])}
                
                # Detect new processes
                for pid, process in current_processes.items():
                    if pid not in self.monitored_processes:
                        await self._analyze_new_process(process)
                        
                self.monitored_processes = current_processes
                await asyncio.sleep(1)
                
            except Exception as e:
                logging.error(f"Process monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _analyze_new_process(self, process):
        """Analyze new process for suspicious patterns"""
        try:
            info = process.info
            if info['cmdline']:
                command = ' '.join(info['cmdline'])
                self.command_history.append({
                    'timestamp': time.time(),
                    'pid': info['pid'],
                    'command': command,
                    'user': info['username'],
                    'process_name': info['name']
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

class FileSystemMonitor:
    """Monitor file system for TTP indicators"""
    
    def __init__(self):
        self.watched_paths = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/var/spool/cron/crontabs', '/etc/crontab',
            '/home/*/.ssh/', '/root/.ssh/',
            '/tmp', '/var/tmp'
        ]
        self.file_events = deque(maxlen=1000)
        
    async def start_monitoring(self):
        """Start file system monitoring (simplified implementation)"""
        # In production, this would use inotify or similar file system monitoring
        while True:
            try:
                await self._check_critical_files()
                await asyncio.sleep(5)
            except Exception as e:
                logging.error(f"File system monitoring error: {e}")
                await asyncio.sleep(10)
    
    async def _check_critical_files(self):
        """Check critical files for modifications"""
        critical_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
        
        for file_path in critical_files:
            try:
                if os.path.exists(file_path):
                    stat_info = os.stat(file_path)
                    self.file_events.append({
                        'timestamp': time.time(),
                        'path': file_path,
                        'mtime': stat_info.st_mtime,
                        'size': stat_info.st_size,
                        'event_type': 'check'
                    })
            except Exception as e:
                logging.error(f"Error checking {file_path}: {e}")

class NetworkConnectionMonitor:
    """Monitor network connections for TTP indicators"""
    
    def __init__(self):
        self.connections = deque(maxlen=1000)
        
    async def start_monitoring(self):
        """Start network connection monitoring"""
        while True:
            try:
                current_connections = psutil.net_connections(kind='inet')
                
                for conn in current_connections:
                    if conn.status == 'ESTABLISHED':
                        self.connections.append({
                            'timestamp': time.time(),
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                            'pid': conn.pid,
                            'status': conn.status
                        })
                
                await asyncio.sleep(2)
                
            except Exception as e:
                logging.error(f"Network monitoring error: {e}")
                await asyncio.sleep(5)

class TTPDetectionEngine:
    """Main TTP detection engine"""
    
    def __init__(self):
        self.mitre_db = MITRETechniqueDB()
        self.process_monitor = ProcessMonitor()
        self.file_monitor = FileSystemMonitor()
        self.network_monitor = NetworkConnectionMonitor()
        
        self.detected_events = deque(maxlen=5000)
        self.attack_chains = {}
        self.running = False
        
        # Detection statistics
        self.stats = {
            'events_detected': 0,
            'attack_chains_identified': 0,
            'techniques_seen': set(),
            'tactics_seen': set()
        }
    
    async def start(self):
        """Start TTP detection engine"""
        self.running = True
        logging.info("TTP Detection Engine started")
        
        # Start all monitoring components
        tasks = [
            asyncio.create_task(self.process_monitor.start_monitoring()),
            asyncio.create_task(self.file_monitor.start_monitoring()),
            asyncio.create_task(self.network_monitor.start_monitoring()),
            asyncio.create_task(self._detection_loop())
        ]
        
        await asyncio.gather(*tasks)
    
    async def stop(self):
        """Stop TTP detection engine"""
        self.running = False
        logging.info("TTP Detection Engine stopped")
    
    async def _detection_loop(self):
        """Main detection loop"""
        while self.running:
            try:
                # Analyze recent command history
                await self._analyze_command_patterns()
                
                # Analyze file system events
                await self._analyze_file_events()
                
                # Analyze network connections
                await self._analyze_network_patterns()
                
                # Update attack chains
                await self._update_attack_chains()
                
                await asyncio.sleep(5)
                
            except Exception as e:
                logging.error(f"Detection loop error: {e}")
                await asyncio.sleep(10)
    
    async def _analyze_command_patterns(self):
        """Analyze command patterns for TTP indicators"""
        recent_commands = list(self.process_monitor.command_history)[-50:]
        
        for cmd_info in recent_commands:
            command = cmd_info['command']
            
            # Check each technique's detection rules
            for technique_id, rules in self.mitre_db.detection_rules.items():
                for rule in rules:
                    if rule['rule_type'] == 'command_pattern':
                        if re.search(rule['pattern'], command, re.IGNORECASE):
                            await self._create_ttp_event(
                                technique_id=technique_id,
                                confidence=rule['confidence'],
                                source_process=cmd_info['process_name'],
                                source_user=cmd_info['user'],
                                indicators={
                                    'command': command,
                                    'pattern_matched': rule['pattern'],
                                    'description': rule['description']
                                },
                                raw_data=cmd_info
                            )
    
    async def _analyze_file_events(self):
        """Analyze file system events for TTP indicators"""
        recent_events = list(self.file_monitor.file_events)[-20:]
        
        for event in recent_events:
            file_path = event['path']
            
            # Check for sensitive file access
            if file_path == '/etc/shadow':
                await self._create_ttp_event(
                    technique_id='T1003.008',
                    confidence=0.9,
                    indicators={
                        'file_accessed': file_path,
                        'event_type': event['event_type']
                    },
                    raw_data=event
                )
    
    async def _analyze_network_patterns(self):
        """Analyze network patterns for TTP indicators"""
        recent_connections = list(self.network_monitor.connections)[-20:]
        
        for conn in recent_connections:
            if conn['remote_addr'] and ':22' in conn['remote_addr']:
                await self._create_ttp_event(
                    technique_id='T1021.004',
                    confidence=0.3,
                    indicators={
                        'connection_type': 'SSH',
                        'remote_addr': conn['remote_addr'],
                        'local_addr': conn['local_addr']
                    },
                    raw_data=conn
                )
    
    async def _create_ttp_event(self, technique_id: str, confidence: float, **kwargs):
        """Create a TTP detection event"""
        technique_info = self.mitre_db.get_technique(technique_id)
        if not technique_info:
            return
        
        event = TTPEvent(
            timestamp=time.time(),
            technique_id=technique_id,
            technique_name=technique_info['name'],
            tactic=technique_info['tactic'],
            severity=int(confidence * 10),
            confidence=confidence,
            **kwargs
        )
        
        self.detected_events.append(event)
        self.stats['events_detected'] += 1
        self.stats['techniques_seen'].add(technique_id)
        self.stats['tactics_seen'].add(technique_info['tactic'])
        
        logging.info(f"TTP Detected: {technique_id} - {technique_info['name']} (confidence: {confidence:.2f})")
        
        # Add to attack chain analysis
        await self._add_to_attack_chain(event)
    
    async def _add_to_attack_chain(self, event: TTPEvent):
        """Add event to attack chain analysis"""
        # Simple attack chain logic - group by source IP or user within time window
        chain_key = event.source_ip or event.source_user or 'unknown'
        
        if chain_key not in self.attack_chains:
            chain_id = hashlib.md5(f"{chain_key}_{event.timestamp}".encode()).hexdigest()[:12]
            self.attack_chains[chain_key] = AttackChain(
                chain_id=chain_id,
                start_time=event.timestamp,
                last_activity=event.timestamp,
                attacker_ip=event.source_ip
            )
            self.stats['attack_chains_identified'] += 1
        
        chain = self.attack_chains[chain_key]
        chain.events.append(event)
        chain.tactics_seen.add(event.tactic)
        chain.techniques_used.append(event.technique_id)
        chain.last_activity = event.timestamp
        
        # Update chain severity based on tactics progression
        chain.severity = len(chain.tactics_seen) + max(e.severity for e in chain.events) // 2
        
        # Check if chain indicates active attack
        time_window = 3600  # 1 hour
        if event.timestamp - chain.start_time < time_window and len(chain.tactics_seen) >= 3:
            logging.warning(f"Active attack chain detected: {chain.chain_id} with {len(chain.tactics_seen)} tactics")
    
    async def _update_attack_chains(self):
        """Update and cleanup attack chains"""
        current_time = time.time()
        inactive_threshold = 7200  # 2 hours
        
        # Mark chains as inactive if no recent activity
        for chain in self.attack_chains.values():
            if current_time - chain.last_activity > inactive_threshold:
                chain.active = False
    
    def get_recent_events(self, limit: int = 50) -> List[TTPEvent]:
        """Get recent TTP detection events"""
        return list(self.detected_events)[-limit:]
    
    def get_active_attack_chains(self) -> List[AttackChain]:
        """Get currently active attack chains"""
        return [chain for chain in self.attack_chains.values() if chain.active]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics"""
        return {
            **self.stats,
            'techniques_seen': list(self.stats['techniques_seen']),
            'tactics_seen': [t.value for t in self.stats['tactics_seen']],
            'active_chains': len([c for c in self.attack_chains.values() if c.active]),
            'total_chains': len(self.attack_chains)
        }
    
    async def hunt_for_technique(self, technique_id: str) -> List[TTPEvent]:
        """Proactive hunt for specific technique"""
        logging.info(f"Starting threat hunt for technique {technique_id}")
        
        rules = self.mitre_db.get_detection_rules(technique_id)
        if not rules:
            logging.warning(f"No detection rules found for {technique_id}")
            return []
        
        matches = []
        
        # Search command history
        for cmd_info in self.process_monitor.command_history:
            command = cmd_info['command']
            for rule in rules:
                if rule['rule_type'] == 'command_pattern':
                    if re.search(rule['pattern'], command, re.IGNORECASE):
                        event = TTPEvent(
                            timestamp=cmd_info['timestamp'],
                            technique_id=technique_id,
                            technique_name=self.mitre_db.get_technique(technique_id)['name'],
                            tactic=self.mitre_db.get_technique(technique_id)['tactic'],
                            severity=int(rule['confidence'] * 10),
                            confidence=rule['confidence'],
                            source_process=cmd_info['process_name'],
                            source_user=cmd_info['user'],
                            indicators={
                                'hunt_result': True,
                                'command': command,
                                'pattern_matched': rule['pattern']
                            },
                            raw_data=cmd_info
                        )
                        matches.append(event)
        
        logging.info(f"Threat hunt for {technique_id} found {len(matches)} matches")
        return matches

# Example usage and testing
if __name__ == "__main__":
    async def main():
        # Initialize TTP detection engine
        detector = TTPDetectionEngine()
        
        # Start detection (this would run continuously)
        try:
            await asyncio.wait_for(detector.start(), timeout=10.0)
        except asyncio.TimeoutError:
            print("Demo timeout - stopping detection engine")
            await detector.stop()
        
        # Show statistics
        stats = detector.get_statistics()
        print(f"Detection Statistics: {json.dumps(stats, indent=2)}")
        
        # Show recent events
        recent_events = detector.get_recent_events(10)
        print(f"Recent Events: {len(recent_events)}")
        for event in recent_events:
            print(f"  {event.technique_id}: {event.technique_name} (confidence: {event.confidence:.2f})")
        
        # Show active attack chains
        active_chains = detector.get_active_attack_chains()
        print(f"Active Attack Chains: {len(active_chains)}")
        for chain in active_chains:
            print(f"  Chain {chain.chain_id}: {len(chain.tactics_seen)} tactics, {len(chain.events)} events")
    
    asyncio.run(main())