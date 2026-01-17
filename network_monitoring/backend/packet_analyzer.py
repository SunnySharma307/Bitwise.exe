from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from datetime import datetime
import ipaddress
from collections import defaultdict

class PacketAnalyzer:
    def __init__(self, syn_detector, attack_classifier, firewall_manager, firestore_logger):
        self.syn_detector = syn_detector
        self.attack_classifier = attack_classifier
        self.firewall_manager = firewall_manager
        self.firestore_logger = firestore_logger
        self.connections = defaultdict(list)
        self.packet_count = 0
        self.attack_count = 0
    
    def analyze_pcap(self, filepath):
        """
        Analyze PCAP file and detect attacks
        """
        try:
            packets = rdpcap(filepath)
            results = {
                'total_packets': len(packets),
                'analyzed_packets': 0,
                'attacks_detected': 0,
                'blocked_ips': [],
                'connections': [],
                'attack_types': defaultdict(int)
            }
            
            for packet in packets:
                if IP in packet:
                    self._process_packet(packet, results)
            
            results['attacks_detected'] = self.attack_count
            results['connections'] = self._format_connections()
            
            return results
            
        except Exception as e:
            print(f"Error analyzing PCAP: {str(e)}")
            raise
    
    def _process_packet(self, packet, results):
        """
        Process individual packet
        """
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            timestamp = datetime.now()
            
            results['analyzed_packets'] += 1
            
            # Store connection info
            self.connections[src_ip].append({
                'dst_ip': dst_ip,
                'timestamp': timestamp.isoformat(),
                'protocol': self._get_protocol(packet)
            })
            
            # Check for TCP SYN packets
            if TCP in packet and packet[TCP].flags == 0x02:
                syn_result = self.syn_detector.check_syn_flood(src_ip, packet)
                
                if syn_result['is_attack']:
                    self.attack_count += 1
                    results['attacks_detected'] += 1
                    results['attack_types']['SYN Flood'] += 1
                    
                    # Classify attack
                    attack_info = self.attack_classifier.classify_attack(
                        'SYN Flood', 
                        src_ip, 
                        packet
                    )
                    
                    # Log to Firestore
                    self.firestore_logger.log_attack({
                        'timestamp': timestamp.isoformat(),
                        'attack_type': 'SYN Flood',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'classification': attack_info['classification'],
                        'confidence': attack_info['confidence'],
                        'description': attack_info['description'],
                        'packet_details': {
                            'size': len(packet),
                            'protocol': 'TCP',
                            'flags': str(packet[TCP].flags)
                        }
                    })
                    
                    # Block IP if not already blocked
                    if src_ip not in results['blocked_ips']:
                        block_result = self.firewall_manager.block_ip(src_ip)
                        results['blocked_ips'].append(src_ip)
                        
            # Check for UDP floods
            elif UDP in packet:
                if self._detect_udp_flood(src_ip):
                    self.attack_count += 1
                    results['attacks_detected'] += 1
                    results['attack_types']['UDP Flood'] += 1
                    
                    # Classify and log
                    attack_info = self.attack_classifier.classify_attack(
                        'UDP Flood',
                        src_ip,
                        packet
                    )
                    
                    self.firestore_logger.log_attack({
                        'timestamp': timestamp.isoformat(),
                        'attack_type': 'UDP Flood',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'classification': attack_info['classification'],
                        'confidence': attack_info['confidence'],
                        'description': attack_info['description']
                    })
                    
        except Exception as e:
            print(f"Error processing packet: {str(e)}")
    
    def _get_protocol(self, packet):
        """
        Get protocol from packet
        """
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        else:
            return 'OTHER'
    
    def _detect_udp_flood(self, src_ip):
        """
        Detect UDP flood attacks
        """
        # Simple threshold: more than 10 UDP packets from same IP
        recent_packets = [p for p in self.connections[src_ip] 
                         if p['protocol'] == 'UDP']
        return len(recent_packets) > 10
    
    def _format_connections(self):
        """
        Format connections for frontend display
        """
        formatted = []
        for src_ip, conns in list(self.connections.items())[:50]:  # Limit to 50
            for conn in conns[:10]:  # Limit connections per IP
                formatted.append({
                    'source': src_ip,
                    'destination': conn['dst_ip'],
                    'timestamp': conn['timestamp'],
                    'protocol': conn['protocol']
                })
        return formatted
    
    def get_connections(self):
        """
        Get connection data for visualization
        """
        return self._format_connections()