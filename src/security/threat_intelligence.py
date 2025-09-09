#!/usr/bin/env python3
"""
LiDiS Intelligent Threat Intelligence Agent

Autonomous threat intelligence gathering, analysis, and application system:
- Multi-source threat intelligence aggregation
- AI-powered intelligence analysis and correlation
- Automated IOC (Indicators of Compromise) extraction
- Real-time threat landscape monitoring
- Automated security rule generation and deployment
- Threat actor tracking and attribution
"""

import asyncio
import aiohttp
import logging
import json
import time
import hashlib
import re
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin
import sqlite3
import threading
from pathlib import Path

@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_id: str
    ioc_type: str  # ip, domain, hash, url, email, etc.
    value: str
    confidence: float  # 0.0-1.0
    severity: int     # 1-10
    description: str
    source: str
    first_seen: float
    last_seen: float
    tags: List[str] = field(default_factory=list)
    threat_types: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

@dataclass  
class ThreatReport:
    """Threat intelligence report"""
    report_id: str
    title: str
    source: str
    publication_date: float
    content: str
    threat_actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    severity_score: int = 1
    confidence_score: float = 0.0
    processed: bool = False

@dataclass
class ThreatActor:
    """Threat actor profile"""
    actor_id: str
    name: str
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    first_observed: float = 0.0
    last_activity: float = 0.0
    sophistication: str = "unknown"  # low, medium, high, expert
    motivations: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    associated_iocs: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)

@dataclass
class SecurityRule:
    """Generated security detection rule"""
    rule_id: str
    rule_type: str  # snort, suricata, yara, sigma, custom
    title: str
    description: str
    rule_content: str
    iocs_referenced: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    confidence: float = 0.0
    created_time: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    deployed: bool = False

class ThreatIntelligenceDB:
    """Threat intelligence database manager"""
    
    def __init__(self, db_path: str = "lidis_threat_intel.db"):
        self.db_path = db_path
        self.conn = None
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for threat intelligence"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        
        # Create tables
        self.conn.executescript('''
            CREATE TABLE IF NOT EXISTS iocs (
                ioc_id TEXT PRIMARY KEY,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence REAL,
                severity INTEGER,
                description TEXT,
                source TEXT,
                first_seen REAL,
                last_seen REAL,
                tags TEXT,
                threat_types TEXT,
                mitre_techniques TEXT
            );
            
            CREATE TABLE IF NOT EXISTS threat_reports (
                report_id TEXT PRIMARY KEY,
                title TEXT,
                source TEXT,
                publication_date REAL,
                content TEXT,
                threat_actors TEXT,
                campaigns TEXT,
                mitre_techniques TEXT,
                severity_score INTEGER,
                confidence_score REAL,
                processed BOOLEAN
            );
            
            CREATE TABLE IF NOT EXISTS threat_actors (
                actor_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                aliases TEXT,
                description TEXT,
                first_observed REAL,
                last_activity REAL,
                sophistication TEXT,
                motivations TEXT,
                targets TEXT,
                ttps TEXT,
                associated_iocs TEXT,
                campaigns TEXT
            );
            
            CREATE TABLE IF NOT EXISTS security_rules (
                rule_id TEXT PRIMARY KEY,
                rule_type TEXT,
                title TEXT,
                description TEXT,
                rule_content TEXT,
                iocs_referenced TEXT,
                mitre_techniques TEXT,
                confidence REAL,
                created_time REAL,
                last_updated REAL,
                deployed BOOLEAN
            );
            
            CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type);
            CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value);
            CREATE INDEX IF NOT EXISTS idx_report_source ON threat_reports(source);
            CREATE INDEX IF NOT EXISTS idx_actor_name ON threat_actors(name);
        ''')
        
        self.conn.commit()
    
    def store_ioc(self, ioc: IOC):
        """Store IOC in database"""
        self.conn.execute('''
            INSERT OR REPLACE INTO iocs 
            (ioc_id, ioc_type, value, confidence, severity, description, source, 
             first_seen, last_seen, tags, threat_types, mitre_techniques)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ioc.ioc_id, ioc.ioc_type, ioc.value, ioc.confidence, ioc.severity,
            ioc.description, ioc.source, ioc.first_seen, ioc.last_seen,
            json.dumps(ioc.tags), json.dumps(ioc.threat_types), 
            json.dumps(ioc.mitre_techniques)
        ))
        self.conn.commit()
    
    def get_iocs_by_type(self, ioc_type: str) -> List[IOC]:
        """Get IOCs by type"""
        cursor = self.conn.execute('SELECT * FROM iocs WHERE ioc_type = ?', (ioc_type,))
        return [self._row_to_ioc(row) for row in cursor.fetchall()]
    
    def search_iocs(self, value: str) -> List[IOC]:
        """Search for IOCs by value"""
        cursor = self.conn.execute('SELECT * FROM iocs WHERE value LIKE ?', (f'%{value}%',))
        return [self._row_to_ioc(row) for row in cursor.fetchall()]
    
    def _row_to_ioc(self, row) -> IOC:
        """Convert database row to IOC object"""
        return IOC(
            ioc_id=row['ioc_id'],
            ioc_type=row['ioc_type'], 
            value=row['value'],
            confidence=row['confidence'],
            severity=row['severity'],
            description=row['description'],
            source=row['source'],
            first_seen=row['first_seen'],
            last_seen=row['last_seen'],
            tags=json.loads(row['tags']) if row['tags'] else [],
            threat_types=json.loads(row['threat_types']) if row['threat_types'] else [],
            mitre_techniques=json.loads(row['mitre_techniques']) if row['mitre_techniques'] else []
        )
    
    def store_threat_report(self, report: ThreatReport):
        """Store threat report in database"""
        self.conn.execute('''
            INSERT OR REPLACE INTO threat_reports
            (report_id, title, source, publication_date, content, threat_actors,
             campaigns, mitre_techniques, severity_score, confidence_score, processed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            report.report_id, report.title, report.source, report.publication_date,
            report.content, json.dumps(report.threat_actors), json.dumps(report.campaigns),
            json.dumps(report.mitre_techniques), report.severity_score, 
            report.confidence_score, report.processed
        ))
        self.conn.commit()

class ThreatIntelligenceCollector:
    """Collect threat intelligence from multiple sources"""
    
    def __init__(self, db: ThreatIntelligenceDB):
        self.db = db
        self.sources = {
            'alienvault': {
                'url': 'https://otx.alienvault.com/api/v1/indicators/export',
                'type': 'json',
                'enabled': True,
                'api_key': None  # Would need API key
            },
            'emergingthreats': {
                'url': 'https://rules.emergingthreats.net/blockrules/emerging-botcc.rules',
                'type': 'text',
                'enabled': True,
                'api_key': None
            },
            'malwaredomains': {
                'url': 'http://www.malwaredomains.com/files/domains.txt',
                'type': 'text',
                'enabled': True,
                'api_key': None
            },
            'abuse_ch': {
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                'type': 'text', 
                'enabled': True,
                'api_key': None
            }
        }
        self.collection_stats = defaultdict(int)
    
    async def collect_all_sources(self) -> Dict[str, List[IOC]]:
        """Collect from all enabled sources"""
        results = {}
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            for source_name, source_config in self.sources.items():
                if source_config['enabled']:
                    try:
                        logging.info(f"Collecting from {source_name}")
                        iocs = await self._collect_from_source(session, source_name, source_config)
                        results[source_name] = iocs
                        self.collection_stats[f"{source_name}_collected"] += len(iocs)
                        
                        # Store in database
                        for ioc in iocs:
                            self.db.store_ioc(ioc)
                            
                    except Exception as e:
                        logging.error(f"Failed to collect from {source_name}: {e}")
                        self.collection_stats[f"{source_name}_errors"] += 1
        
        return results
    
    async def _collect_from_source(self, session: aiohttp.ClientSession, 
                                 source_name: str, source_config: Dict[str, Any]) -> List[IOC]:
        """Collect IOCs from a specific source"""
        iocs = []
        
        try:
            headers = {}
            if source_config.get('api_key'):
                headers['X-OTX-API-KEY'] = source_config['api_key']
            
            async with session.get(source_config['url'], headers=headers) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    if source_config['type'] == 'json':
                        iocs = await self._parse_json_source(content, source_name)
                    elif source_config['type'] == 'text':
                        iocs = await self._parse_text_source(content, source_name)
                        
                else:
                    logging.warning(f"HTTP {response.status} from {source_name}")
                    
        except Exception as e:
            logging.error(f"Error collecting from {source_name}: {e}")
        
        return iocs
    
    async def _parse_json_source(self, content: str, source_name: str) -> List[IOC]:
        """Parse JSON threat intelligence source"""
        iocs = []
        
        try:
            data = json.loads(content)
            
            # AlienVault OTX format example
            if isinstance(data, dict) and 'results' in data:
                for indicator in data['results']:
                    ioc = IOC(
                        ioc_id=hashlib.md5(f"{source_name}_{indicator.get('indicator', '')}".encode()).hexdigest(),
                        ioc_type=indicator.get('type', 'unknown').lower(),
                        value=indicator.get('indicator', ''),
                        confidence=float(indicator.get('confidence', 50)) / 100,
                        severity=min(10, int(indicator.get('severity', 3))),
                        description=indicator.get('description', ''),
                        source=source_name,
                        first_seen=time.time(),
                        last_seen=time.time(),
                        tags=indicator.get('tags', [])
                    )
                    iocs.append(ioc)
                    
        except Exception as e:
            logging.error(f"Error parsing JSON from {source_name}: {e}")
        
        return iocs
    
    async def _parse_text_source(self, content: str, source_name: str) -> List[IOC]:
        """Parse text-based threat intelligence source"""
        iocs = []
        
        try:
            lines = content.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Detect IOC type based on content
                ioc_type, confidence = self._detect_ioc_type(line)
                
                if ioc_type != 'unknown':
                    ioc = IOC(
                        ioc_id=hashlib.md5(f"{source_name}_{line}".encode()).hexdigest(),
                        ioc_type=ioc_type,
                        value=line,
                        confidence=confidence,
                        severity=5,  # Default severity
                        description=f"IOC from {source_name}",
                        source=source_name,
                        first_seen=time.time(),
                        last_seen=time.time()
                    )
                    iocs.append(ioc)
                    
        except Exception as e:
            logging.error(f"Error parsing text from {source_name}: {e}")
        
        return iocs
    
    def _detect_ioc_type(self, value: str) -> Tuple[str, float]:
        """Detect IOC type from value"""
        value = value.strip()
        
        # IP address
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', value):
            return 'ip', 0.9
        
        # Domain
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', value):
            return 'domain', 0.8
        
        # URL
        if value.startswith(('http://', 'https://', 'ftp://')):
            return 'url', 0.9
        
        # Hash (MD5, SHA1, SHA256)
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return 'md5', 0.9
        elif re.match(r'^[a-fA-F0-9]{40}$', value):
            return 'sha1', 0.9
        elif re.match(r'^[a-fA-F0-9]{64}$', value):
            return 'sha256', 0.9
        
        # Email
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return 'email', 0.8
        
        return 'unknown', 0.0

class ThreatIntelligenceAnalyzer:
    """Analyze and correlate threat intelligence data"""
    
    def __init__(self, db: ThreatIntelligenceDB):
        self.db = db
        self.analysis_patterns = {
            'apt_indicators': [
                'targeted attack', 'apt', 'advanced persistent',
                'nation state', 'espionage', 'cyber warfare'
            ],
            'malware_families': [
                'ransomware', 'trojan', 'botnet', 'rootkit',
                'backdoor', 'keylogger', 'stealer', 'loader'
            ],
            'attack_techniques': [
                'phishing', 'spear phishing', 'watering hole',
                'supply chain', 'zero-day', 'lateral movement'
            ]
        }
    
    async def analyze_ioc_relationships(self) -> Dict[str, Any]:
        """Analyze relationships between IOCs"""
        analysis_results = {
            'ip_to_domains': defaultdict(list),
            'domain_clusters': defaultdict(list),
            'hash_families': defaultdict(list),
            'temporal_patterns': [],
            'geographic_distribution': defaultdict(int)
        }
        
        # Get all IOCs
        all_iocs = []
        for ioc_type in ['ip', 'domain', 'md5', 'sha1', 'sha256', 'url']:
            all_iocs.extend(self.db.get_iocs_by_type(ioc_type))
        
        # Analyze IP to domain relationships
        ip_iocs = [ioc for ioc in all_iocs if ioc.ioc_type == 'ip']
        domain_iocs = [ioc for ioc in all_iocs if ioc.ioc_type == 'domain']
        
        for ip_ioc in ip_iocs:
            for domain_ioc in domain_iocs:
                # Simple correlation based on source and timing
                if (ip_ioc.source == domain_ioc.source and 
                    abs(ip_ioc.first_seen - domain_ioc.first_seen) < 3600):  # 1 hour window
                    analysis_results['ip_to_domains'][ip_ioc.value].append(domain_ioc.value)
        
        # Cluster similar domains
        for domain_ioc in domain_iocs:
            domain_parts = domain_ioc.value.split('.')
            if len(domain_parts) >= 2:
                root_domain = '.'.join(domain_parts[-2:])
                analysis_results['domain_clusters'][root_domain].append(domain_ioc.value)
        
        return analysis_results
    
    async def generate_threat_summary(self) -> Dict[str, Any]:
        """Generate threat intelligence summary"""
        summary = {
            'total_iocs': 0,
            'ioc_breakdown': defaultdict(int),
            'high_confidence_iocs': 0,
            'recent_activity': [],
            'top_sources': defaultdict(int),
            'threat_trends': {}
        }
        
        # Get recent IOCs (last 24 hours)
        recent_threshold = time.time() - 86400
        
        for ioc_type in ['ip', 'domain', 'md5', 'sha1', 'sha256', 'url', 'email']:
            iocs = self.db.get_iocs_by_type(ioc_type)
            summary['total_iocs'] += len(iocs)
            summary['ioc_breakdown'][ioc_type] = len(iocs)
            
            for ioc in iocs:
                if ioc.confidence >= 0.8:
                    summary['high_confidence_iocs'] += 1
                
                if ioc.first_seen >= recent_threshold:
                    summary['recent_activity'].append({
                        'type': ioc.ioc_type,
                        'value': ioc.value[:50],  # Truncate for safety
                        'confidence': ioc.confidence,
                        'source': ioc.source
                    })
                
                summary['top_sources'][ioc.source] += 1
        
        return summary

class SecurityRuleGenerator:
    """Generate security rules from threat intelligence"""
    
    def __init__(self, db: ThreatIntelligenceDB):
        self.db = db
        self.rule_templates = {
            'snort_ip': 'alert tcp any any -> {ip} any (msg:"LiDiS: Malicious IP {ip} detected"; sid:{sid}; rev:1; classtype:trojan-activity;)',
            'snort_domain': 'alert dns any any -> any any (msg:"LiDiS: Malicious domain {domain} queried"; content:"{domain}"; sid:{sid}; rev:1; classtype:trojan-activity;)',
            'suricata_tls': 'alert tls any any -> any any (msg:"LiDiS: TLS connection to malicious domain {domain}"; tls.sni; content:"{domain}"; sid:{sid}; rev:1; classtype:trojan-activity;)',
            'yara_hash': '''rule Malware_{hash_short} {{
    meta:
        description = "LiDiS: Detected malicious file hash {hash}"
        source = "LiDiS Threat Intelligence"
        confidence = "{confidence}"
    condition:
        hash.md5(0, filesize) == "{hash}" or
        hash.sha1(0, filesize) == "{hash}" or
        hash.sha256(0, filesize) == "{hash}"
}}'''
        }
        self.next_sid = 2000000  # Starting SID for LiDiS rules
    
    async def generate_rules_from_iocs(self, min_confidence: float = 0.7) -> List[SecurityRule]:
        """Generate security rules from high-confidence IOCs"""
        rules = []
        
        # Generate IP-based rules
        ip_iocs = [ioc for ioc in self.db.get_iocs_by_type('ip') if ioc.confidence >= min_confidence]
        for ioc in ip_iocs[:100]:  # Limit to prevent rule explosion
            rule = SecurityRule(
                rule_id=f"lidis_ip_{ioc.ioc_id}",
                rule_type="snort",
                title=f"Malicious IP {ioc.value}",
                description=f"Detect communication with malicious IP {ioc.value}",
                rule_content=self.rule_templates['snort_ip'].format(
                    ip=ioc.value, 
                    sid=self.next_sid
                ),
                iocs_referenced=[ioc.ioc_id],
                confidence=ioc.confidence
            )
            rules.append(rule)
            self.next_sid += 1
        
        # Generate domain-based rules
        domain_iocs = [ioc for ioc in self.db.get_iocs_by_type('domain') if ioc.confidence >= min_confidence]
        for ioc in domain_iocs[:100]:
            # Snort rule for DNS
            dns_rule = SecurityRule(
                rule_id=f"lidis_domain_dns_{ioc.ioc_id}",
                rule_type="snort",
                title=f"Malicious domain DNS query {ioc.value}",
                description=f"Detect DNS queries for malicious domain {ioc.value}",
                rule_content=self.rule_templates['snort_domain'].format(
                    domain=ioc.value,
                    sid=self.next_sid
                ),
                iocs_referenced=[ioc.ioc_id],
                confidence=ioc.confidence
            )
            rules.append(dns_rule)
            self.next_sid += 1
            
            # Suricata rule for TLS
            tls_rule = SecurityRule(
                rule_id=f"lidis_domain_tls_{ioc.ioc_id}",
                rule_type="suricata",
                title=f"Malicious domain TLS {ioc.value}",
                description=f"Detect TLS connections to malicious domain {ioc.value}",
                rule_content=self.rule_templates['suricata_tls'].format(
                    domain=ioc.value,
                    sid=self.next_sid
                ),
                iocs_referenced=[ioc.ioc_id],
                confidence=ioc.confidence
            )
            rules.append(tls_rule)
            self.next_sid += 1
        
        # Generate hash-based YARA rules
        for hash_type in ['md5', 'sha1', 'sha256']:
            hash_iocs = [ioc for ioc in self.db.get_iocs_by_type(hash_type) if ioc.confidence >= min_confidence]
            for ioc in hash_iocs[:50]:  # Limit YARA rules
                rule = SecurityRule(
                    rule_id=f"lidis_hash_{ioc.ioc_id}",
                    rule_type="yara",
                    title=f"Malicious file hash {hash_type.upper()}",
                    description=f"Detect file with malicious {hash_type.upper()} hash {ioc.value}",
                    rule_content=self.rule_templates['yara_hash'].format(
                        hash_short=ioc.value[:8],
                        hash=ioc.value,
                        confidence=ioc.confidence
                    ),
                    iocs_referenced=[ioc.ioc_id],
                    confidence=ioc.confidence
                )
                rules.append(rule)
        
        return rules
    
    async def deploy_rules(self, rules: List[SecurityRule], rule_type: str) -> Dict[str, Any]:
        """Deploy generated rules to security systems"""
        deployment_results = {
            'deployed_count': 0,
            'failed_count': 0,
            'errors': []
        }
        
        # In production, this would integrate with actual security systems
        # For now, we'll simulate deployment
        
        for rule in rules:
            if rule.rule_type == rule_type or rule_type == 'all':
                try:
                    # Simulate rule deployment
                    await asyncio.sleep(0.1)  # Simulate deployment time
                    
                    # Mark as deployed
                    rule.deployed = True
                    rule.last_updated = time.time()
                    
                    deployment_results['deployed_count'] += 1
                    logging.info(f"Deployed rule {rule.rule_id}")
                    
                except Exception as e:
                    deployment_results['failed_count'] += 1
                    deployment_results['errors'].append(f"Failed to deploy {rule.rule_id}: {e}")
                    logging.error(f"Failed to deploy rule {rule.rule_id}: {e}")
        
        return deployment_results

class ThreatIntelligenceAgent:
    """Main threat intelligence agent orchestrating all components"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._default_config()
        
        self.db = ThreatIntelligenceDB(self.config.get('db_path', 'lidis_threat_intel.db'))
        self.collector = ThreatIntelligenceCollector(self.db)
        self.analyzer = ThreatIntelligenceAnalyzer(self.db)
        self.rule_generator = SecurityRuleGenerator(self.db)
        
        self.running = False
        self.collection_task = None
        self.analysis_task = None
        
        # Statistics
        self.stats = {
            'collection_cycles': 0,
            'total_iocs_collected': 0,
            'rules_generated': 0,
            'rules_deployed': 0,
            'last_collection_time': 0,
            'last_analysis_time': 0
        }
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            'collection_interval': 3600,  # 1 hour
            'analysis_interval': 7200,    # 2 hours
            'rule_generation_interval': 14400,  # 4 hours
            'min_confidence_for_rules': 0.7,
            'auto_deploy_rules': False,
            'max_rules_per_cycle': 1000
        }
    
    async def start(self):
        """Start the threat intelligence agent"""
        self.running = True
        logging.info("Threat Intelligence Agent started")
        
        # Start background tasks
        self.collection_task = asyncio.create_task(self._collection_loop())
        self.analysis_task = asyncio.create_task(self._analysis_loop())
        
        await asyncio.gather(self.collection_task, self.analysis_task)
    
    async def stop(self):
        """Stop the threat intelligence agent"""
        self.running = False
        
        if self.collection_task:
            self.collection_task.cancel()
        if self.analysis_task:
            self.analysis_task.cancel()
        
        logging.info("Threat Intelligence Agent stopped")
    
    async def _collection_loop(self):
        """Background threat intelligence collection loop"""
        while self.running:
            try:
                logging.info("Starting threat intelligence collection cycle")
                
                # Collect from all sources
                collection_results = await self.collector.collect_all_sources()
                
                # Update statistics
                total_collected = sum(len(iocs) for iocs in collection_results.values())
                self.stats['total_iocs_collected'] += total_collected
                self.stats['collection_cycles'] += 1
                self.stats['last_collection_time'] = time.time()
                
                logging.info(f"Collection cycle completed: {total_collected} IOCs collected")
                
                # Wait for next collection cycle
                await asyncio.sleep(self.config['collection_interval'])
                
            except Exception as e:
                logging.error(f"Collection loop error: {e}")
                await asyncio.sleep(600)  # Wait 10 minutes on error
    
    async def _analysis_loop(self):
        """Background threat intelligence analysis loop"""
        while self.running:
            try:
                logging.info("Starting threat intelligence analysis cycle")
                
                # Analyze IOC relationships
                relationships = await self.analyzer.analyze_ioc_relationships()
                
                # Generate threat summary
                summary = await self.analyzer.generate_threat_summary()
                
                # Generate security rules
                if self.stats['collection_cycles'] > 0:  # Only after first collection
                    rules = await self.rule_generator.generate_rules_from_iocs(
                        min_confidence=self.config['min_confidence_for_rules']
                    )
                    
                    # Limit rules to prevent overload
                    rules = rules[:self.config['max_rules_per_cycle']]
                    
                    self.stats['rules_generated'] += len(rules)
                    
                    # Auto-deploy if enabled
                    if self.config['auto_deploy_rules'] and rules:
                        deployment_results = await self.rule_generator.deploy_rules(rules, 'all')
                        self.stats['rules_deployed'] += deployment_results['deployed_count']
                        logging.info(f"Auto-deployed {deployment_results['deployed_count']} rules")
                
                self.stats['last_analysis_time'] = time.time()
                
                logging.info(f"Analysis cycle completed: {summary['total_iocs']} total IOCs")
                
                # Wait for next analysis cycle
                await asyncio.sleep(self.config['analysis_interval'])
                
            except Exception as e:
                logging.error(f"Analysis loop error: {e}")
                await asyncio.sleep(600)  # Wait 10 minutes on error
    
    async def manual_collection(self) -> Dict[str, Any]:
        """Trigger manual threat intelligence collection"""
        logging.info("Manual threat intelligence collection triggered")
        
        try:
            collection_results = await self.collector.collect_all_sources()
            
            total_collected = sum(len(iocs) for iocs in collection_results.values())
            self.stats['total_iocs_collected'] += total_collected
            
            return {
                'success': True,
                'iocs_collected': total_collected,
                'sources': list(collection_results.keys()),
                'timestamp': time.time()
            }
            
        except Exception as e:
            logging.error(f"Manual collection failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': time.time()
            }
    
    async def search_threats(self, query: str) -> Dict[str, Any]:
        """Search threat intelligence database"""
        try:
            iocs = self.db.search_iocs(query)
            
            return {
                'query': query,
                'results_count': len(iocs),
                'iocs': [asdict(ioc) for ioc in iocs[:50]],  # Limit results
                'timestamp': time.time()
            }
            
        except Exception as e:
            logging.error(f"Threat search failed: {e}")
            return {
                'query': query,
                'error': str(e),
                'timestamp': time.time()
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        return {
            **self.stats,
            'uptime': time.time() - getattr(self, 'start_time', time.time()),
            'collection_status': 'running' if self.running else 'stopped'
        }

# Example usage and testing
if __name__ == "__main__":
    async def main():
        # Initialize threat intelligence agent
        agent = ThreatIntelligenceAgent({
            'collection_interval': 60,  # 1 minute for demo
            'analysis_interval': 120,   # 2 minutes for demo
            'auto_deploy_rules': False
        })
        
        # Start agent for a short time
        try:
            await asyncio.wait_for(agent.start(), timeout=10.0)
        except asyncio.TimeoutError:
            print("Demo timeout - stopping agent")
            await agent.stop()
        
        # Show statistics
        stats = agent.get_statistics()
        print(f"Agent Statistics: {json.dumps(stats, indent=2)}")
        
        # Manual collection demo
        collection_result = await agent.manual_collection()
        print(f"Manual Collection: {json.dumps(collection_result, indent=2)}")
        
        # Search demo
        search_result = await agent.search_threats("malware")
        print(f"Search Results: {json.dumps(search_result, indent=2)}")
    
    asyncio.run(main())