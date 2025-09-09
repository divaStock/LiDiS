#!/usr/bin/env python3
"""
LiDiS IPS Engine
Advanced Intrusion Prevention System with AI/ML capabilities

This module implements the core IPS functionality including:
- Real-time packet analysis
- Behavioral anomaly detection
- Machine learning-based threat classification
- Automated response mechanisms
"""

import asyncio
import logging
import json
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import hashlib

@dataclass
class NetworkPacket:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload_size: int
    flags: List[str]
    payload_hash: str
    
@dataclass 
class ThreatEvent:
    timestamp: float
    threat_type: str
    severity: int  # 1-10 scale
    source_ip: str
    target_ip: str
    description: str
    indicators: Dict[str, Any]
    confidence: float
    mitigated: bool = False

class BehavioralAnalyzer:
    """Analyzes network behavior for anomaly detection"""
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.packet_history = deque(maxlen=window_size)
        self.connection_profiles = defaultdict(dict)
        self.anomaly_detector = IsolationForest(
            contamination=0.1, 
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def extract_features(self, packet: NetworkPacket) -> np.ndarray:
        """Extract behavioral features from network packet"""
        src_profile = self.connection_profiles.get(packet.src_ip, {})
        
        features = [
            packet.payload_size,
            packet.src_port,
            packet.dst_port,
            hash(packet.protocol) % 1000,
            len(packet.flags),
            src_profile.get('avg_packet_size', packet.payload_size),
            src_profile.get('connection_count', 1),
            src_profile.get('unique_ports', 1),
            int(time.time() % 86400),  # Time of day feature
            len(set(p.dst_ip for p in list(self.packet_history)[-100:] if p.src_ip == packet.src_ip))
        ]
        
        return np.array(features).reshape(1, -1)
    
    def update_profiles(self, packet: NetworkPacket):
        """Update connection profiles for behavioral analysis"""
        profile = self.connection_profiles[packet.src_ip]
        
        if 'packet_sizes' not in profile:
            profile['packet_sizes'] = deque(maxlen=100)
            profile['ports'] = set()
            profile['connection_count'] = 0
            
        profile['packet_sizes'].append(packet.payload_size)
        profile['ports'].add(packet.dst_port)
        profile['connection_count'] += 1
        profile['avg_packet_size'] = sum(profile['packet_sizes']) / len(profile['packet_sizes'])
        profile['unique_ports'] = len(profile['ports'])
        profile['last_seen'] = packet.timestamp
    
    def analyze_packet(self, packet: NetworkPacket) -> Tuple[bool, float]:
        """Analyze packet for behavioral anomalies"""
        self.packet_history.append(packet)
        self.update_profiles(packet)
        
        if len(self.packet_history) < 100:
            return False, 0.0
            
        if not self.is_trained and len(self.packet_history) >= 500:
            self.train_model()
            
        if not self.is_trained:
            return False, 0.0
            
        features = self.extract_features(packet)
        features_scaled = self.scaler.transform(features)
        
        anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
        is_anomaly = self.anomaly_detector.predict(features_scaled)[0] == -1
        
        # Convert anomaly score to confidence (0-1 range)
        confidence = max(0, min(1, (anomaly_score + 0.5) * 2))
        
        return is_anomaly, confidence
    
    def train_model(self):
        """Train the anomaly detection model on recent packet history"""
        if len(self.packet_history) < 100:
            return
            
        features_list = []
        for packet in self.packet_history:
            features = self.extract_features(packet)
            features_list.append(features.flatten())
            
        X = np.array(features_list)
        X_scaled = self.scaler.fit_transform(X)
        
        self.anomaly_detector.fit(X_scaled)
        self.is_trained = True
        logging.info(f"Behavioral analyzer trained on {len(X)} samples")

class ThreatClassifier:
    """ML-based threat classification system"""
    
    def __init__(self):
        self.classifier = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            random_state=42
        )
        self.threat_types = [
            'port_scan', 'dos_attack', 'brute_force', 'malware_communication',
            'data_exfiltration', 'lateral_movement', 'command_control',
            'privilege_escalation', 'persistence', 'defense_evasion'
        ]
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def extract_threat_features(self, packets: List[NetworkPacket]) -> np.ndarray:
        """Extract features for threat classification"""
        if not packets:
            return np.zeros(15).reshape(1, -1)
            
        features = [
            len(packets),  # Number of packets
            len(set(p.dst_port for p in packets)),  # Unique destination ports
            len(set(p.dst_ip for p in packets)),    # Unique destination IPs  
            sum(p.payload_size for p in packets),   # Total payload size
            np.mean([p.payload_size for p in packets]),  # Average payload size
            np.std([p.payload_size for p in packets]),   # Payload size variance
            len(set(p.protocol for p in packets)),       # Unique protocols
            packets[-1].timestamp - packets[0].timestamp,  # Time span
            sum(1 for p in packets if p.src_port < 1024),  # Privileged source ports
            sum(1 for p in packets if p.dst_port < 1024),  # Privileged dest ports
            len(set(p.payload_hash for p in packets)),     # Unique payload hashes
            sum(1 for p in packets if 'SYN' in p.flags),   # SYN flags
            sum(1 for p in packets if 'RST' in p.flags),   # RST flags
            sum(1 for p in packets if 'FIN' in p.flags),   # FIN flags
            sum(1 for p in packets if len(p.flags) > 2)    # Complex flag combinations
        ]
        
        # Handle NaN values
        features = [f if not np.isnan(f) else 0 for f in features]
        return np.array(features).reshape(1, -1)
    
    def classify_threat(self, packets: List[NetworkPacket]) -> Tuple[str, float]:
        """Classify threat type and confidence"""
        if not self.is_trained:
            return 'unknown', 0.0
            
        features = self.extract_threat_features(packets)
        features_scaled = self.scaler.transform(features)
        
        probabilities = self.classifier.predict_proba(features_scaled)[0]
        max_prob_idx = np.argmax(probabilities)
        threat_type = self.threat_types[max_prob_idx]
        confidence = probabilities[max_prob_idx]
        
        return threat_type, confidence
    
    def load_model(self, model_path: str):
        """Load pre-trained classification model"""
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
                self.classifier = model_data['classifier']
                self.scaler = model_data['scaler']
                self.threat_types = model_data['threat_types']
                self.is_trained = True
                logging.info(f"Loaded threat classification model from {model_path}")
        except Exception as e:
            logging.error(f"Failed to load model: {e}")

class ResponseEngine:
    """Automated response and mitigation system"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.rate_limits = defaultdict(list)
        self.response_actions = {
            'block_ip': self._block_ip,
            'rate_limit': self._apply_rate_limit, 
            'quarantine': self._quarantine_connection,
            'alert': self._generate_alert,
            'log': self._log_event
        }
        
    async def respond_to_threat(self, threat: ThreatEvent) -> List[str]:
        """Execute appropriate response actions for detected threat"""
        actions_taken = []
        
        # Determine response based on threat type and severity
        if threat.severity >= 8:
            actions_taken.extend(await self._execute_action('block_ip', threat))
            actions_taken.extend(await self._execute_action('alert', threat))
        elif threat.severity >= 5:
            actions_taken.extend(await self._execute_action('rate_limit', threat))
            actions_taken.extend(await self._execute_action('quarantine', threat))
        
        # Always log the event
        actions_taken.extend(await self._execute_action('log', threat))
        
        return actions_taken
    
    async def _execute_action(self, action_type: str, threat: ThreatEvent) -> List[str]:
        """Execute specific response action"""
        if action_type in self.response_actions:
            return await self.response_actions[action_type](threat)
        return []
    
    async def _block_ip(self, threat: ThreatEvent) -> List[str]:
        """Block IP address using iptables"""
        try:
            cmd = f"iptables -A INPUT -s {threat.source_ip} -j DROP"
            # In production, this would execute the actual iptables command
            self.blocked_ips.add(threat.source_ip)
            logging.warning(f"Blocked IP {threat.source_ip} due to {threat.threat_type}")
            return [f"blocked_ip:{threat.source_ip}"]
        except Exception as e:
            logging.error(f"Failed to block IP {threat.source_ip}: {e}")
            return []
    
    async def _apply_rate_limit(self, threat: ThreatEvent) -> List[str]:
        """Apply rate limiting to source IP"""
        try:
            self.rate_limits[threat.source_ip].append(time.time())
            # Clean old entries (older than 1 hour)
            cutoff = time.time() - 3600
            self.rate_limits[threat.source_ip] = [
                t for t in self.rate_limits[threat.source_ip] if t > cutoff
            ]
            logging.info(f"Applied rate limiting to {threat.source_ip}")
            return [f"rate_limited:{threat.source_ip}"]
        except Exception as e:
            logging.error(f"Failed to apply rate limit: {e}")
            return []
    
    async def _quarantine_connection(self, threat: ThreatEvent) -> List[str]:
        """Quarantine suspicious connection"""
        try:
            # In production, this would implement actual quarantine logic
            logging.info(f"Quarantined connection from {threat.source_ip}")
            return [f"quarantined:{threat.source_ip}"]
        except Exception as e:
            logging.error(f"Failed to quarantine connection: {e}")
            return []
    
    async def _generate_alert(self, threat: ThreatEvent) -> List[str]:
        """Generate security alert"""
        try:
            alert_data = {
                'timestamp': threat.timestamp,
                'type': threat.threat_type,
                'severity': threat.severity,
                'source': threat.source_ip,
                'target': threat.target_ip,
                'description': threat.description,
                'confidence': threat.confidence
            }
            
            # In production, this would send to SIEM/alerting system
            logging.critical(f"SECURITY ALERT: {json.dumps(alert_data)}")
            return [f"alert_generated:{threat.threat_type}"]
        except Exception as e:
            logging.error(f"Failed to generate alert: {e}")
            return []
    
    async def _log_event(self, threat: ThreatEvent) -> List[str]:
        """Log security event"""
        try:
            log_entry = {
                'timestamp': threat.timestamp,
                'event_type': 'security_threat',
                'threat_data': asdict(threat)
            }
            
            # In production, this would write to security log
            logging.info(f"Security event logged: {json.dumps(log_entry)}")
            return [f"logged:{threat.threat_type}"]
        except Exception as e:
            logging.error(f"Failed to log event: {e}")
            return []

class IPSEngine:
    """Main IPS Engine orchestrating all security components"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._default_config()
        self.behavioral_analyzer = BehavioralAnalyzer(
            window_size=self.config.get('behavioral_window_size', 1000)
        )
        self.threat_classifier = ThreatClassifier()
        self.response_engine = ResponseEngine()
        
        self.packet_buffer = deque(maxlen=100)
        self.threat_events = deque(maxlen=1000)
        self.is_running = False
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'threats_mitigated': 0,
            'false_positives': 0
        }
        
        # Load pre-trained models if available
        model_path = self.config.get('threat_model_path')
        if model_path:
            self.threat_classifier.load_model(model_path)
    
    def _default_config(self) -> Dict[str, Any]:
        """Default IPS configuration"""
        return {
            'behavioral_window_size': 1000,
            'threat_threshold': 0.7,
            'max_packet_buffer': 100,
            'enable_auto_response': True,
            'log_level': 'INFO'
        }
    
    async def process_packet(self, packet: NetworkPacket) -> Optional[ThreatEvent]:
        """Process incoming network packet for threats"""
        self.stats['packets_processed'] += 1
        self.packet_buffer.append(packet)
        
        # Behavioral analysis
        is_anomaly, anomaly_confidence = self.behavioral_analyzer.analyze_packet(packet)
        
        if not is_anomaly or anomaly_confidence < self.config['threat_threshold']:
            return None
        
        # Threat classification on recent packets from same source
        source_packets = [p for p in self.packet_buffer if p.src_ip == packet.src_ip][-20:]
        threat_type, classification_confidence = self.threat_classifier.classify_threat(source_packets)
        
        # Combined confidence score
        combined_confidence = (anomaly_confidence + classification_confidence) / 2
        
        if combined_confidence >= self.config['threat_threshold']:
            # Create threat event
            threat = ThreatEvent(
                timestamp=packet.timestamp,
                threat_type=threat_type,
                severity=int(combined_confidence * 10),
                source_ip=packet.src_ip,
                target_ip=packet.dst_ip,
                description=f"{threat_type} detected from {packet.src_ip}",
                indicators={
                    'anomaly_confidence': anomaly_confidence,
                    'classification_confidence': classification_confidence,
                    'packet_count': len(source_packets),
                    'protocols': list(set(p.protocol for p in source_packets))
                },
                confidence=combined_confidence
            )
            
            self.threat_events.append(threat)
            self.stats['threats_detected'] += 1
            
            # Automated response if enabled
            if self.config['enable_auto_response']:
                actions = await self.response_engine.respond_to_threat(threat)
                if actions:
                    threat.mitigated = True
                    self.stats['threats_mitigated'] += 1
            
            return threat
        
        return None
    
    async def start(self):
        """Start the IPS engine"""
        self.is_running = True
        logging.info("LiDiS IPS Engine started")
        
        # In production, this would start packet capture and processing
        # For now, this is a placeholder for the main processing loop
        
    async def stop(self):
        """Stop the IPS engine"""
        self.is_running = False
        logging.info("LiDiS IPS Engine stopped")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current IPS statistics"""
        return {
            **self.stats,
            'active_threats': len([t for t in self.threat_events if not t.mitigated]),
            'blocked_ips': len(self.response_engine.blocked_ips),
            'uptime': time.time() - getattr(self, 'start_time', time.time())
        }
    
    def get_recent_threats(self, limit: int = 50) -> List[ThreatEvent]:
        """Get recent threat events"""
        return list(self.threat_events)[-limit:]

# Example usage and testing
if __name__ == "__main__":
    async def main():
        # Initialize IPS engine
        ips = IPSEngine({
            'threat_threshold': 0.6,
            'enable_auto_response': True
        })
        
        await ips.start()
        
        # Simulate some network packets
        test_packets = [
            NetworkPacket(
                timestamp=time.time(),
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1", 
                src_port=12345,
                dst_port=22,
                protocol="TCP",
                payload_size=64,
                flags=["SYN"],
                payload_hash=hashlib.md5(b"test").hexdigest()
            )
        ]
        
        for packet in test_packets:
            threat = await ips.process_packet(packet)
            if threat:
                print(f"Threat detected: {threat.threat_type} (confidence: {threat.confidence:.2f})")
        
        print(f"Statistics: {ips.get_statistics()}")
        
        await ips.stop()
    
    asyncio.run(main())