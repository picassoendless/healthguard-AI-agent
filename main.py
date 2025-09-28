#!/usr/bin/env python3
"""
CyberGuard AI Agent - Advanced Cybersecurity Monitoring System
Author: [Your Name]
Date: 2024

An intelligent AI-powered cybersecurity monitoring system that uses machine learning
and behavioral analysis to detect, analyze, and respond to security threats in real-time.

Key Features:
- Real-time network traffic analysis
- AI-powered threat detection using anomaly detection
- Behavioral pattern analysis
- Automated incident response
- Risk scoring and assessment
- Integration with threat intelligence feeds
"""

import asyncio
import json
import logging
import sqlite3
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import hashlib
import random
import re
import socket
import subprocess
import sys
from pathlib import Path

# Try to import ML libraries, fall back to simplified mode if not available
try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
    print("✅ Machine Learning libraries loaded")
except ImportError as e:
    ML_AVAILABLE = False
    print("⚠️  ML libraries not available - using rule-based detection")
    print("   Install with: pip install numpy pandas scikit-learn")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("⚠️  psutil not available - system metrics will be simulated")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("⚠️  requests not available - using local threat intelligence")


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cyberguard.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class ThreatEvent:
    """Represents a security threat event."""
    id: str
    timestamp: datetime
    threat_type: str
    severity: str  # Critical, High, Medium, Low
    source_ip: str
    destination_ip: str
    port: int
    description: str
    confidence_score: float
    status: str  # Active, Mitigated, Investigating
    mitigation_actions: List[str]


@dataclass
class NetworkPacket:
    """Represents a network packet for analysis."""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_size: int
    flags: str


class ThreatIntelligence:
    """Threat intelligence integration and management."""
    
    def __init__(self):
        self.malicious_ips = set()
        self.malicious_domains = set()
        self.known_attack_signatures = {}
        self.load_threat_feeds()
    
    def load_threat_feeds(self):
        """Load threat intelligence feeds."""
        # Simulated threat intelligence data
        self.malicious_ips.update([
            "192.168.1.100", "10.0.0.50", "203.45.67.89",
            "185.220.101.50", "91.235.116.45"
        ])
        
        self.malicious_domains.update([
            "malicious-site.com", "phishing-bank.net", 
            "fake-security.org", "scam-download.io"
        ])
        
        self.known_attack_signatures.update({
            "sql_injection": r"(\bunion\b.*\bselect\b|\bor\b.*\b1=1\b)",
            "xss_attack": r"(<script|javascript:|onerror=|onload=)",
            "command_injection": r"(;|\||\&\&|\|\|).*?(cat|ls|pwd|whoami|id)",
            "directory_traversal": r"(\.\.\/|\.\.\\)",
            "brute_force_pattern": r"(admin|root|administrator).*?(password|123456|admin)"
        })
        
        logger.info(f"Loaded {len(self.malicious_ips)} malicious IPs and {len(self.malicious_domains)} domains")
    
    def is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is in threat intelligence feeds."""
        return ip in self.malicious_ips
    
    def check_attack_signature(self, data: str) -> Tuple[bool, str]:
        """Check data against known attack signatures."""
        for attack_type, pattern in self.known_attack_signatures.items():
            if re.search(pattern, data, re.IGNORECASE):
                return True, attack_type
        return False, ""


class AIThreatDetector:
    """AI-powered threat detection using machine learning or rule-based fallback."""
    
    def __init__(self):
        self.is_trained = False
        self.feature_history = deque(maxlen=1000)
        self.baseline_metrics = {}
        self.anomaly_threshold = -0.5
        
        if ML_AVAILABLE:
            self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
            self.scaler = StandardScaler()
            self.ml_mode = True
            logger.info("AI Detector initialized with ML capabilities")
        else:
            # Fallback to rule-based detection
            self.ml_mode = False
            self.connection_tracking = defaultdict(lambda: {"count": 0, "first_seen": None, "ports": set()})
            logger.info("AI Detector initialized in rule-based mode")
    
    def extract_features(self, packet: NetworkPacket) -> 'np.array':
        """Extract features from network packet for ML analysis."""
        if not ML_AVAILABLE:
            return None
            
        features = [
            packet.packet_size,
            packet.source_port,
            packet.destination_port,
            hash(packet.source_ip) % 1000,  # IP hash for anonymization
            hash(packet.destination_ip) % 1000,
            len(packet.flags) if packet.flags else 0,
            packet.timestamp.hour,
            packet.timestamp.weekday(),
        ]
        return np.array(features)
    
    def train_model(self, packets: List[NetworkPacket]):
        """Train the anomaly detection model."""
        if not self.ml_mode or len(packets) < 50:
            if not self.ml_mode:
                logger.info("Skipping ML training - using rule-based detection")
            else:
                logger.warning("Insufficient data for training. Need at least 50 packets.")
            return
        
        features = [self.extract_features(packet) for packet in packets]
        feature_matrix = np.array(features)
        
        # Normalize features
        feature_matrix = self.scaler.fit_transform(feature_matrix)
        
        # Train isolation forest
        self.isolation_forest.fit(feature_matrix)
        self.is_trained = True
        
        logger.info(f"AI model trained with {len(packets)} packets")
    
    def predict_anomaly(self, packet: NetworkPacket) -> Tuple[bool, float]:
        """Predict if packet is anomalous using ML or rule-based detection."""
        if self.ml_mode and self.is_trained and ML_AVAILABLE:
            # Use ML prediction
            features = self.extract_features(packet).reshape(1, -1)
            features = self.scaler.transform(features)
            
            anomaly_score = self.isolation_forest.decision_function(features)[0]
            is_anomaly = anomaly_score < self.anomaly_threshold
            confidence = abs(anomaly_score)
            
            return is_anomaly, confidence
        else:
            # Use rule-based detection
            return self._rule_based_detection(packet)
    
    def _rule_based_detection(self, packet: NetworkPacket) -> Tuple[bool, float]:
        """Rule-based anomaly detection fallback."""
        anomaly_score = 0.0
        
        # Suspicious ports
        high_risk_ports = [22, 23, 135, 139, 445, 1433, 3306, 3389]
        if packet.destination_port in high_risk_ports:
            anomaly_score += 0.3
        
        # Off-hours activity
        if packet.timestamp.hour < 6 or packet.timestamp.hour > 22:
            anomaly_score += 0.2
        
        # Large packet size
        if packet.packet_size > 1200:
            anomaly_score += 0.1
        
        # Connection tracking
        conn_key = packet.source_ip
        self.connection_tracking[conn_key]["count"] += 1
        self.connection_tracking[conn_key]["ports"].add(packet.destination_port)
        
        if self.connection_tracking[conn_key]["first_seen"] is None:
            self.connection_tracking[conn_key]["first_seen"] = packet.timestamp
        
        # High frequency connections
        conn_count = self.connection_tracking[conn_key]["count"]
        if conn_count > 50:  # High connection count
            anomaly_score += 0.4
        
        # Port scanning
        ports_accessed = len(self.connection_tracking[conn_key]["ports"])
        if ports_accessed > 10:
            anomaly_score += 0.5
        
        is_anomaly = anomaly_score > 0.4
        return is_anomaly, anomaly_score


class NetworkMonitor:
    """Network traffic monitoring and analysis."""
    
    def __init__(self):
        self.packet_buffer = deque(maxlen=10000)
        self.connection_tracking = defaultdict(int)
        self.suspicious_activities = []
        self.monitoring_active = False
        
    def simulate_network_traffic(self) -> NetworkPacket:
        """Simulate network traffic for demonstration."""
        protocols = ["TCP", "UDP", "HTTP", "HTTPS", "DNS"]
        
        # Generate realistic IP addresses
        source_ip = f"192.168.1.{random.randint(1, 254)}"
        dest_ip = f"10.0.0.{random.randint(1, 100)}"
        
        # Occasionally generate suspicious traffic
        if random.random() < 0.1:  # 10% chance of suspicious activity
            source_ip = random.choice(["192.168.1.100", "203.45.67.89"])  # Known malicious IPs
            dest_port = random.choice([22, 23, 3389, 1433, 3306])  # Common attack ports
        else:
            dest_port = random.choice([80, 443, 53, 22, 25, 110, 143])
        
        packet = NetworkPacket(
            timestamp=datetime.now(),
            source_ip=source_ip,
            destination_ip=dest_ip,
            source_port=random.randint(1024, 65535),
            destination_port=dest_port,
            protocol=random.choice(protocols),
            packet_size=random.randint(64, 1500),
            flags=random.choice(["SYN", "ACK", "FIN", "RST", "PSH", ""])
        )
        
        return packet
    
    def analyze_traffic_patterns(self) -> Dict:
        """Analyze network traffic for suspicious patterns."""
        if len(self.packet_buffer) < 100:
            return {}
        
        recent_packets = list(self.packet_buffer)[-100:]
        
        # Connection frequency analysis
        connection_counts = defaultdict(int)
        port_scan_detection = defaultdict(set)
        
        for packet in recent_packets:
            connection_key = f"{packet.source_ip}->{packet.destination_ip}"
            connection_counts[connection_key] += 1
            port_scan_detection[packet.source_ip].add(packet.destination_port)
        
        # Detect potential port scans
        port_scanners = []
        for ip, ports in port_scan_detection.items():
            if len(ports) > 10:  # Accessing more than 10 different ports
                port_scanners.append(ip)
        
        # Detect high-frequency connections (potential DDoS)
        high_freq_connections = [
            conn for conn, count in connection_counts.items() 
            if count > 20
        ]
        
        analysis = {
            "total_packets": len(recent_packets),
            "unique_connections": len(connection_counts),
            "port_scanners": port_scanners,
            "high_frequency_connections": high_freq_connections,
            "top_talkers": sorted(connection_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        }
        
        return analysis
    
    async def start_monitoring(self):
        """Start network monitoring loop."""
        self.monitoring_active = True
        logger.info("Network monitoring started")
        
        while self.monitoring_active:
            # Simulate packet capture
            packet = self.simulate_network_traffic()
            self.packet_buffer.append(packet)
            
            # Small delay to simulate realistic traffic
            await asyncio.sleep(0.1)
    
    def stop_monitoring(self):
        """Stop network monitoring."""
        self.monitoring_active = False
        logger.info("Network monitoring stopped")


class IncidentResponse:
    """Automated incident response system."""
    
    def __init__(self):
        self.response_actions = {
            "block_ip": self._block_ip,
            "rate_limit": self._apply_rate_limit,
            "alert_admin": self._alert_admin,
            "quarantine": self._quarantine_system,
            "log_incident": self._log_incident
        }
        self.blocked_ips = set()
    
    def _block_ip(self, ip: str) -> bool:
        """Block IP address (simulation)."""
        self.blocked_ips.add(ip)
        logger.info(f"BLOCKED IP: {ip}")
        return True
    
    def _apply_rate_limit(self, ip: str) -> bool:
        """Apply rate limiting to IP (simulation)."""
        logger.info(f"RATE LIMITED: {ip}")
        return True
    
    def _alert_admin(self, threat: ThreatEvent) -> bool:
        """Send alert to administrator (simulation)."""
        logger.warning(f"ADMIN ALERT: {threat.threat_type} from {threat.source_ip}")
        return True
    
    def _quarantine_system(self, system_id: str) -> bool:
        """Quarantine affected system (simulation)."""
        logger.critical(f"QUARANTINED SYSTEM: {system_id}")
        return True
    
    def _log_incident(self, threat: ThreatEvent) -> bool:
        """Log incident to security database."""
        logger.info(f"LOGGED INCIDENT: {threat.id} - {threat.description}")
        return True
    
    def execute_response(self, threat: ThreatEvent) -> List[str]:
        """Execute automated response based on threat severity."""
        executed_actions = []
        
        # Determine response based on severity
        if threat.severity == "Critical":
            actions = ["block_ip", "quarantine", "alert_admin", "log_incident"]
        elif threat.severity == "High":
            actions = ["block_ip", "alert_admin", "log_incident"]
        elif threat.severity == "Medium":
            actions = ["rate_limit", "log_incident"]
        else:
            actions = ["log_incident"]
        
        for action in actions:
            if action in self.response_actions:
                success = self.response_actions[action](threat.source_ip if action in ["block_ip", "rate_limit"] else threat)
                if success:
                    executed_actions.append(action)
        
        return executed_actions


class SecurityDatabase:
    """SQLite database for storing security events and analytics."""
    
    def __init__(self, db_path: str = "cyberguard.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Threat events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    threat_type TEXT,
                    severity TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    port INTEGER,
                    description TEXT,
                    confidence_score REAL,
                    status TEXT,
                    mitigation_actions TEXT
                )
            """)
            
            # System metrics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_metrics (
                    timestamp TEXT,
                    cpu_usage REAL,
                    memory_usage REAL,
                    network_connections INTEGER,
                    active_threats INTEGER
                )
            """)
            
            conn.commit()
    
    def store_threat_event(self, threat: ThreatEvent):
        """Store threat event in database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO threat_events 
                (id, timestamp, threat_type, severity, source_ip, destination_ip, 
                 port, description, confidence_score, status, mitigation_actions)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                threat.id, threat.timestamp.isoformat(), threat.threat_type,
                threat.severity, threat.source_ip, threat.destination_ip,
                threat.port, threat.description, threat.confidence_score,
                threat.status, json.dumps(threat.mitigation_actions)
            ))
            conn.commit()
    
    def get_threat_statistics(self) -> Dict:
        """Get threat statistics for dashboard."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Active threats count
            cursor.execute("SELECT COUNT(*) FROM threat_events WHERE status = 'Active'")
            active_threats = cursor.fetchone()[0]
            
            # Threats by severity
            cursor.execute("SELECT severity, COUNT(*) FROM threat_events GROUP BY severity")
            severity_counts = dict(cursor.fetchall())
            
            # Recent threats (last 24 hours)
            yesterday = (datetime.now() - timedelta(days=1)).isoformat()
            cursor.execute("SELECT COUNT(*) FROM threat_events WHERE timestamp > ?", (yesterday,))
            recent_threats = cursor.fetchone()[0]
            
            return {
                "active_threats": active_threats,
                "severity_distribution": severity_counts,
                "recent_threats_24h": recent_threats
            }


class CyberGuardAI:
    """Main CyberGuard AI Agent orchestrator."""
    
    def __init__(self):
        self.network_monitor = NetworkMonitor()
        self.ai_detector = AIThreatDetector()
        self.threat_intel = ThreatIntelligence()
        self.incident_response = IncidentResponse()
        self.database = SecurityDatabase()
        
        self.active_threats = []
        self.system_health = {"status": "Healthy", "uptime": time.time()}
        self.monitoring_tasks = []
        self.is_running = False
    
    def calculate_risk_score(self, packet: NetworkPacket, is_anomaly: bool, confidence: float) -> Tuple[str, float]:
        """Calculate threat risk score and severity."""
        base_score = 0.0
        
        # Factor in AI anomaly detection
        if is_anomaly:
            base_score += confidence * 40
        
        # Factor in threat intelligence
        if self.threat_intel.is_malicious_ip(packet.source_ip):
            base_score += 30
        
        # Factor in port analysis
        high_risk_ports = [22, 23, 135, 139, 445, 1433, 3306, 3389]
        if packet.destination_port in high_risk_ports:
            base_score += 20
        
        # Factor in time of day (attacks often happen off-hours)
        hour = packet.timestamp.hour
        if hour < 6 or hour > 22:
            base_score += 10
        
        # Determine severity
        if base_score >= 80:
            severity = "Critical"
        elif base_score >= 60:
            severity = "High"
        elif base_score >= 40:
            severity = "Medium"
        else:
            severity = "Low"
        
        return severity, base_score
    
    def create_threat_event(self, packet: NetworkPacket, threat_type: str, severity: str, 
                          confidence: float, description: str) -> ThreatEvent:
        """Create a new threat event."""
        threat_id = hashlib.md5(
            f"{packet.source_ip}{packet.destination_ip}{packet.timestamp}".encode()
        ).hexdigest()[:8]
        
        threat = ThreatEvent(
            id=threat_id,
            timestamp=packet.timestamp,
            threat_type=threat_type,
            severity=severity,
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            port=packet.destination_port,
            description=description,
            confidence_score=confidence,
            status="Active",
            mitigation_actions=[]
        )
        
        return threat
    
    async def analyze_packet(self, packet: NetworkPacket):
        """Analyze individual packet for threats."""
        threats_detected = []
        
        # AI-based anomaly detection
        is_anomaly, ai_confidence = self.ai_detector.predict_anomaly(packet)
        
        if is_anomaly:
            severity, risk_score = self.calculate_risk_score(packet, True, ai_confidence)
            threat = self.create_threat_event(
                packet, "Anomalous Behavior", severity, ai_confidence,
                f"AI detected anomalous network behavior from {packet.source_ip}"
            )
            threats_detected.append(threat)
        
        # Threat intelligence check
        if self.threat_intel.is_malicious_ip(packet.source_ip):
            threat = self.create_threat_event(
                packet, "Known Malicious IP", "High", 0.9,
                f"Traffic from known malicious IP: {packet.source_ip}"
            )
            threats_detected.append(threat)
        
        # Port scan detection
        if packet.destination_port in [22, 23, 135, 139, 445]:
            threat = self.create_threat_event(
                packet, "Port Scan", "Medium", 0.6,
                f"Potential port scan targeting port {packet.destination_port}"
            )
            threats_detected.append(threat)
        
        # Process detected threats
        for threat in threats_detected:
            await self.handle_threat(threat)
    
    async def handle_threat(self, threat: ThreatEvent):
        """Handle detected threat with automated response."""
        logger.warning(f"THREAT DETECTED: {threat.threat_type} - {threat.description}")
        
        # Execute automated response
        actions = self.incident_response.execute_response(threat)
        threat.mitigation_actions = actions
        threat.status = "Mitigated" if actions else "Active"
        
        # Store in database
        self.database.store_threat_event(threat)
        
        # Add to active threats if not mitigated
        if threat.status == "Active":
            self.active_threats.append(threat)
    
    async def continuous_monitoring(self):
        """Main monitoring loop."""
        logger.info("Starting continuous security monitoring...")
        
        # Train AI model with initial data
        initial_packets = []
        for _ in range(100):
            packet = self.network_monitor.simulate_network_traffic()
            initial_packets.append(packet)
        
        self.ai_detector.train_model(initial_packets)
        
        # Start network monitoring
        monitor_task = asyncio.create_task(self.network_monitor.start_monitoring())
        self.monitoring_tasks.append(monitor_task)
        
        # Main analysis loop
        while self.is_running:
            try:
                # Analyze recent packets
                if self.network_monitor.packet_buffer:
                    recent_packets = list(self.network_monitor.packet_buffer)[-10:]
                    
                    for packet in recent_packets:
                        await self.analyze_packet(packet)
                    
                    # Perform traffic pattern analysis
                    traffic_analysis = self.network_monitor.analyze_traffic_patterns()
                    
                    if traffic_analysis.get("port_scanners"):
                        for scanner_ip in traffic_analysis["port_scanners"]:
                            threat = ThreatEvent(
                                id=hashlib.md5(f"port_scan_{scanner_ip}_{time.time()}".encode()).hexdigest()[:8],
                                timestamp=datetime.now(),
                                threat_type="Port Scan",
                                severity="High",
                                source_ip=scanner_ip,
                                destination_ip="Multiple",
                                port=0,
                                description=f"Port scanning activity detected from {scanner_ip}",
                                confidence_score=0.85,
                                status="Active",
                                mitigation_actions=[]
                            )
                            await self.handle_threat(threat)
                
                # Update system health
                self.update_system_health()
                
                # Clean up old threats
                self.cleanup_old_threats()
                
                await asyncio.sleep(1)  # Monitor every second
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(5)
    
    def update_system_health(self):
        """Update system health metrics."""
        try:
            if PSUTIL_AVAILABLE:
                cpu_usage = psutil.cpu_percent()
                memory_usage = psutil.virtual_memory().percent
            else:
                # Simulate system metrics
                cpu_usage = random.uniform(10, 80)
                memory_usage = random.uniform(30, 70)
            
            self.system_health.update({
                "cpu_usage": cpu_usage,
                "memory_usage": memory_usage,
                "active_threats": len(self.active_threats),
                "uptime": time.time() - self.system_health["uptime"],
                "status": "Healthy" if len(self.active_threats) < 10 else "Alert"
            })
            
        except Exception as e:
            logger.error(f"Error updating system health: {e}")
    
    def cleanup_old_threats(self):
        """Remove resolved or old threats."""
        current_time = datetime.now()
        self.active_threats = [
            threat for threat in self.active_threats
            if (current_time - threat.timestamp).seconds < 3600  # Keep threats for 1 hour
        ]
    
    def get_dashboard_data(self) -> Dict:
        """Get data for security dashboard."""
        stats = self.database.get_threat_statistics()
        
        return {
            "system_health": self.system_health,
            "active_threats": len(self.active_threats),
            "recent_threats": self.active_threats[-10:],  # Last 10 threats
            "threat_statistics": stats,
            "blocked_ips": list(self.incident_response.blocked_ips),
            "network_stats": self.network_monitor.analyze_traffic_patterns()
        }
    
    async def start(self):
        """Start the CyberGuard AI Agent."""
        self.is_running = True
        logger.info("CyberGuard AI Agent starting...")
        
        try:
            await self.continuous_monitoring()
        except KeyboardInterrupt:
            logger.info("Shutdown requested...")
        except Exception as e:
            logger.error(f"Critical error: {e}")
        finally:
            await self.stop()
    
    async def stop(self):
        """Stop the CyberGuard AI Agent."""
        self.is_running = False
        self.network_monitor.stop_monitoring()
        
        # Cancel monitoring tasks
        for task in self.monitoring_tasks:
            task.cancel()
        
        logger.info("CyberGuard AI Agent stopped")


def print_dashboard(agent: CyberGuardAI):
    """Print a simple text-based dashboard."""
    dashboard = agent.get_dashboard_data()
    
    print("\n" + "="*60)
    print("           CYBERGUARD AI AGENT - SECURITY DASHBOARD")
    print("="*60)
    
    # System Health
    health = dashboard["system_health"]
    print(f"\n🖥️  SYSTEM HEALTH: {health['status']}")
    print(f"   CPU Usage: {health.get('cpu_usage', 0):.1f}%")
    print(f"   Memory Usage: {health.get('memory_usage', 0):.1f}%")
    print(f"   Uptime: {health.get('uptime', 0)/3600:.1f} hours")
    
    # Threat Summary
    print(f"\n🛡️  SECURITY STATUS:")
    print(f"   Active Threats: {dashboard['active_threats']}")
    print(f"   Blocked IPs: {len(dashboard['blocked_ips'])}")
    
    # Recent Threats
    if dashboard["recent_threats"]:
        print(f"\n⚠️  RECENT THREATS:")
        for threat in dashboard["recent_threats"][-5:]:  # Show last 5
            print(f"   [{threat.timestamp.strftime('%H:%M:%S')}] {threat.severity} - {threat.threat_type}")
            print(f"      Source: {threat.source_ip} | {threat.description}")
    
    # Network Stats
    network_stats = dashboard["network_stats"]
    if network_stats:
        print(f"\n🌐 NETWORK ANALYSIS:")
        print(f"   Total Packets: {network_stats.get('total_packets', 0)}")
        print(f"   Unique Connections: {network_stats.get('unique_connections', 0)}")
        if network_stats.get('port_scanners'):
            print(f"   ⚠️  Port Scanners: {', '.join(network_stats['port_scanners'])}")
    
    print("="*60)


async def main():
    """Main function to run CyberGuard AI Agent."""
    print("🛡️  Initializing CyberGuard AI Agent...")
    
    # Create and start the agent
    agent = CyberGuardAI()
    
    # Start dashboard display in separate thread
    def dashboard_loop():
        while agent.is_running:
            print_dashboard(agent)
            time.sleep(10)  # Update dashboard every 10 seconds
    
    dashboard_thread = threading.Thread(target=dashboard_loop, daemon=True)
    dashboard_thread.start()
    
    # Start the agent
    await agent.start()


if __name__ == "__main__":
    print("🛡️  CyberGuard AI Agent")
    print("=" * 50)
    
    # Check dependencies and inform user
    missing_deps = []
    if not ML_AVAILABLE:
        missing_deps.append("ML libraries (numpy, pandas, scikit-learn)")
    if not PSUTIL_AVAILABLE:
        missing_deps.append("psutil")
    if not REQUESTS_AVAILABLE:
        missing_deps.append("requests")
    
    if missing_deps:
        print("⚠️  Some optional dependencies are missing:")
        for dep in missing_deps:
            print(f"   - {dep}")
        print("\n✅ The system will run in simplified mode.")
        print("💡 To install all features: pip install numpy pandas scikit-learn psutil requests")
    else:
        print("✅ All dependencies available - full functionality enabled!")
    
    print("=" * 50)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 CyberGuard AI Agent stopped by user.")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)