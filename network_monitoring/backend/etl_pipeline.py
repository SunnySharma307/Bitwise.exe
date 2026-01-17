"""
ETL Pipeline for Wireshark/PCAP Data to Database

This module provides Extract, Transform, Load functionality to:
1. Extract packets from Wireshark/PCAP files
2. Transform raw packet data into structured format
3. Load transformed data into Firebase Firestore database
"""

import os
import sys
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any, Optional
import json

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, Ether
from firestore_logger import FirestoreLogger


class ETLPipeline:
    """
    ETL Pipeline for processing Wireshark/PCAP data
    """
    
    def __init__(self, firestore_logger: Optional[FirestoreLogger] = None):
        """
        Initialize ETL Pipeline
        
        Args:
            firestore_logger: Optional FirestoreLogger instance
        """
        self.firestore_logger = firestore_logger or FirestoreLogger()
        self.stats = {
            'total_packets': 0,
            'processed_packets': 0,
            'failed_packets': 0,
            'connections_created': 0,
            'attacks_detected': 0,
            'start_time': None,
            'end_time': None
        }
    
    def extract(self, source: str) -> List[Any]:
        """
        Extract packets from Wireshark/PCAP file
        
        Args:
            source: Path to PCAP file or directory containing PCAP files
            
        Returns:
            List of raw packets
        """
        print(f"[EXTRACT] Starting extraction from: {source}")
        self.stats['start_time'] = datetime.now()
        
        packets = []
        
        try:
            if os.path.isfile(source):
                # Single file
                if source.endswith('.pcap') or source.endswith('.pcapng'):
                    print(f"[EXTRACT] Reading PCAP file: {source}")
                    packets = rdpcap(source)
                    print(f"[EXTRACT] Extracted {len(packets)} packets from {source}")
                else:
                    raise ValueError(f"Unsupported file format: {source}")
            
            elif os.path.isdir(source):
                # Directory of files
                print(f"[EXTRACT] Reading directory: {source}")
                pcap_files = [
                    os.path.join(source, f) 
                    for f in os.listdir(source) 
                    if f.endswith('.pcap') or f.endswith('.pcapng')
                ]
                
                if not pcap_files:
                    raise ValueError(f"No PCAP files found in directory: {source}")
                
                print(f"[EXTRACT] Found {len(pcap_files)} PCAP files")
                
                for pcap_file in pcap_files:
                    file_packets = rdpcap(pcap_file)
                    packets.extend(file_packets)
                    print(f"[EXTRACT] Extracted {len(file_packets)} packets from {pcap_file}")
            
            else:
                raise ValueError(f"Source path does not exist: {source}")
            
            self.stats['total_packets'] = len(packets)
            print(f"[EXTRACT] Total packets extracted: {len(packets)}")
            
            return packets
            
        except Exception as e:
            print(f"[EXTRACT] Error extracting packets: {str(e)}")
            raise
    
    def transform(self, packets: List[Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Transform raw packets into structured data
        
        Args:
            packets: List of raw packets from Scapy
            
        Returns:
            Dictionary containing transformed data:
            - packets: List of packet records
            - connections: List of connection records
            - attacks: List of attack records
            - statistics: Aggregated statistics
        """
        print(f"[TRANSFORM] Starting transformation of {len(packets)} packets")
        
        transformed_data = {
            'packets': [],
            'connections': [],
            'attacks': [],
            'statistics': defaultdict(int)
        }
        
        # Track connections
        connections_map = {}
        ip_stats = defaultdict(lambda: {
            'packet_count': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'protocols': set(),
            'ports': set(),
            'first_seen': None,
            'last_seen': None
        })
        
        for idx, packet in enumerate(packets):
            try:
                # Extract packet data
                packet_data = self._transform_packet(packet, idx)
                
                if packet_data:
                    transformed_data['packets'].append(packet_data)
                    self.stats['processed_packets'] += 1
                    
                    # Update IP statistics
                    if 'src_ip' in packet_data:
                        self._update_ip_stats(ip_stats, packet_data, 'src')
                    if 'dst_ip' in packet_data:
                        self._update_ip_stats(ip_stats, packet_data, 'dst')
                    
                    # Track connections
                    if 'src_ip' in packet_data and 'dst_ip' in packet_data:
                        conn_key = self._get_connection_key(
                            packet_data['src_ip'],
                            packet_data['dst_ip'],
                            packet_data.get('protocol', 'UNKNOWN')
                        )
                        
                        if conn_key not in connections_map:
                            connections_map[conn_key] = {
                                'src_ip': packet_data['src_ip'],
                                'dst_ip': packet_data['dst_ip'],
                                'protocol': packet_data.get('protocol', 'UNKNOWN'),
                                'packet_count': 0,
                                'bytes_transferred': 0,
                                'first_seen': packet_data['timestamp'],
                                'last_seen': packet_data['timestamp'],
                                'src_port': packet_data.get('src_port'),
                                'dst_port': packet_data.get('dst_port')
                            }
                            self.stats['connections_created'] += 1
                        
                        connections_map[conn_key]['packet_count'] += 1
                        connections_map[conn_key]['bytes_transferred'] += packet_data.get('packet_size', 0)
                        connections_map[conn_key]['last_seen'] = packet_data['timestamp']
                    
                    # Check for potential attacks
                    attack_data = self._detect_attacks(packet_data, ip_stats)
                    if attack_data:
                        transformed_data['attacks'].append(attack_data)
                        self.stats['attacks_detected'] += 1
                
            except Exception as e:
                self.stats['failed_packets'] += 1
                print(f"[TRANSFORM] Error processing packet {idx}: {str(e)}")
                continue
        
        # Convert connections map to list
        transformed_data['connections'] = list(connections_map.values())
        
        # Add IP statistics
        transformed_data['ip_statistics'] = {
            ip: {
                **stats,
                'protocols': list(stats['protocols']),
                'ports': list(stats['ports'])
            }
            for ip, stats in ip_stats.items()
        }
        
        print(f"[TRANSFORM] Transformation complete:")
        print(f"  - Packets processed: {self.stats['processed_packets']}")
        print(f"  - Connections found: {len(transformed_data['connections'])}")
        print(f"  - Attacks detected: {self.stats['attacks_detected']}")
        print(f"  - Failed packets: {self.stats['failed_packets']}")
        
        return transformed_data
    
    def _transform_packet(self, packet: Any, index: int) -> Optional[Dict[str, Any]]:
        """
        Transform a single packet into structured format
        
        Args:
            packet: Raw packet from Scapy
            index: Packet index in the capture
            
        Returns:
            Dictionary with packet data or None if packet cannot be processed
        """
        try:
            packet_data = {
                'packet_index': index,
                'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                'packet_size': len(packet),
                'raw_size': len(packet)
            }
            
            # Ethernet layer
            if Ether in packet:
                packet_data['src_mac'] = packet[Ether].src
                packet_data['dst_mac'] = packet[Ether].dst
                packet_data['ether_type'] = hex(packet[Ether].type)
            
            # IP layer
            if IP in packet:
                ip_layer = packet[IP]
                packet_data['src_ip'] = ip_layer.src
                packet_data['dst_ip'] = ip_layer.dst
                packet_data['ip_version'] = ip_layer.version
                packet_data['ip_ttl'] = ip_layer.ttl
                packet_data['ip_proto'] = ip_layer.proto
                packet_data['ip_len'] = ip_layer.len
                
                # TCP layer
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    packet_data['protocol'] = 'TCP'
                    packet_data['src_port'] = tcp_layer.sport
                    packet_data['dst_port'] = tcp_layer.dport
                    packet_data['tcp_flags'] = {
                        'syn': bool(tcp_layer.flags & 0x02),
                        'ack': bool(tcp_layer.flags & 0x10),
                        'fin': bool(tcp_layer.flags & 0x01),
                        'rst': bool(tcp_layer.flags & 0x04),
                        'psh': bool(tcp_layer.flags & 0x08),
                        'urg': bool(tcp_layer.flags & 0x20)
                    }
                    packet_data['tcp_seq'] = tcp_layer.seq
                    packet_data['tcp_ack'] = tcp_layer.ack
                    packet_data['tcp_window'] = tcp_layer.window
                
                # UDP layer
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    packet_data['protocol'] = 'UDP'
                    packet_data['src_port'] = udp_layer.sport
                    packet_data['dst_port'] = udp_layer.dport
                    packet_data['udp_len'] = udp_layer.len
                
                # ICMP layer
                elif ICMP in packet:
                    icmp_layer = packet[ICMP]
                    packet_data['protocol'] = 'ICMP'
                    packet_data['icmp_type'] = icmp_layer.type
                    packet_data['icmp_code'] = icmp_layer.code
                
                # ARP layer
                elif ARP in packet:
                    arp_layer = packet[ARP]
                    packet_data['protocol'] = 'ARP'
                    packet_data['arp_op'] = arp_layer.op
                    packet_data['src_mac'] = arp_layer.hwsrc
                    packet_data['dst_mac'] = arp_layer.hwdst
                    packet_data['src_ip'] = arp_layer.psrc
                    packet_data['dst_ip'] = arp_layer.pdst
                
                else:
                    packet_data['protocol'] = 'OTHER'
            
            else:
                # Non-IP packet
                packet_data['protocol'] = 'NON-IP'
            
            return packet_data
            
        except Exception as e:
            print(f"[TRANSFORM] Error transforming packet {index}: {str(e)}")
            return None
    
    def _update_ip_stats(self, ip_stats: Dict, packet_data: Dict, direction: str):
        """Update IP statistics"""
        ip_key = packet_data.get(f'{direction}_ip')
        if not ip_key:
            return
        
        if ip_key not in ip_stats:
            ip_stats[ip_key] = {
                'packet_count': 0,
                'bytes_sent': 0,
                'bytes_received': 0,
                'protocols': set(),
                'ports': set(),
                'first_seen': packet_data['timestamp'],
                'last_seen': packet_data['timestamp']
            }
        
        stats = ip_stats[ip_key]
        stats['packet_count'] += 1
        
        if direction == 'src':
            stats['bytes_sent'] += packet_data.get('packet_size', 0)
        else:
            stats['bytes_received'] += packet_data.get('packet_size', 0)
        
        if 'protocol' in packet_data:
            stats['protocols'].add(packet_data['protocol'])
        
        if f'{direction}_port' in packet_data:
            stats['ports'].add(packet_data[f'{direction}_port'])
        
        stats['last_seen'] = packet_data['timestamp']
        if not stats['first_seen']:
            stats['first_seen'] = packet_data['timestamp']
    
    def _get_connection_key(self, src_ip: str, dst_ip: str, protocol: str) -> str:
        """Generate unique connection key"""
        return f"{src_ip}:{dst_ip}:{protocol}"
    
    def _detect_attacks(self, packet_data: Dict, ip_stats: Dict) -> Optional[Dict]:
        """
        Detect potential attacks in packet data
        
        Args:
            packet_data: Transformed packet data
            ip_stats: IP statistics dictionary
            
        Returns:
            Attack data dictionary or None
        """
        attack_data = None
        src_ip = packet_data.get('src_ip')
        
        if not src_ip:
            return None
        
        # Check for SYN flood (multiple SYN packets)
        if packet_data.get('protocol') == 'TCP':
            tcp_flags = packet_data.get('tcp_flags', {})
            if tcp_flags.get('syn') and not tcp_flags.get('ack'):
                # Check if this IP has sent many SYN packets
                if src_ip in ip_stats:
                    syn_count = ip_stats[src_ip].get('syn_packet_count', 0) + 1
                    ip_stats[src_ip]['syn_packet_count'] = syn_count
                    
                    if syn_count > 5:  # Threshold for SYN flood
                        attack_data = {
                            'attack_type': 'SYN Flood',
                            'source_ip': src_ip,
                            'destination_ip': packet_data.get('dst_ip'),
                            'severity': 'high',
                            'packet_count': syn_count,
                            'timestamp': packet_data['timestamp'],
                            'details': {
                                'protocol': 'TCP',
                                'port': packet_data.get('dst_port'),
                                'flags': tcp_flags
                            }
                        }
        
        # Check for UDP flood
        elif packet_data.get('protocol') == 'UDP':
            if src_ip in ip_stats:
                udp_count = ip_stats[src_ip].get('udp_packet_count', 0) + 1
                ip_stats[src_ip]['udp_packet_count'] = udp_count
                
                if udp_count > 100:  # Threshold for UDP flood
                    attack_data = {
                        'attack_type': 'UDP Flood',
                        'source_ip': src_ip,
                        'destination_ip': packet_data.get('dst_ip'),
                        'severity': 'medium',
                        'packet_count': udp_count,
                        'timestamp': packet_data['timestamp'],
                        'details': {
                            'protocol': 'UDP',
                            'port': packet_data.get('dst_port')
                        }
                    }
        
        return attack_data
    
    def load(self, transformed_data: Dict[str, List[Dict[str, Any]]], 
             batch_size: int = 100) -> Dict[str, Any]:
        """
        Load transformed data into database
        
        Args:
            transformed_data: Transformed data dictionary
            batch_size: Number of records to load per batch
            
        Returns:
            Dictionary with load statistics
        """
        print(f"[LOAD] Starting data load to database")
        
        load_stats = {
            'packets_loaded': 0,
            'connections_loaded': 0,
            'attacks_loaded': 0,
            'errors': 0
        }
        
        try:
            # Load packets in batches
            packets = transformed_data.get('packets', [])
            if packets:
                print(f"[LOAD] Loading {len(packets)} packets in batches of {batch_size}")
                for i in range(0, len(packets), batch_size):
                    batch = packets[i:i + batch_size]
                    self._load_batch('packets', batch)
                    load_stats['packets_loaded'] += len(batch)
                    print(f"[LOAD] Loaded packet batch {i//batch_size + 1} ({len(batch)} packets)")
            
            # Load connections
            connections = transformed_data.get('connections', [])
            if connections:
                print(f"[LOAD] Loading {len(connections)} connections")
                for i in range(0, len(connections), batch_size):
                    batch = connections[i:i + batch_size]
                    self._load_batch('connections', batch)
                    load_stats['connections_loaded'] += len(batch)
                    print(f"[LOAD] Loaded connection batch {i//batch_size + 1} ({len(batch)} connections)")
            
            # Load attacks
            attacks = transformed_data.get('attacks', [])
            if attacks:
                print(f"[LOAD] Loading {len(attacks)} attacks")
                for attack in attacks:
                    try:
                        self.firestore_logger.log_attack(attack)
                        load_stats['attacks_loaded'] += 1
                    except Exception as e:
                        load_stats['errors'] += 1
                        print(f"[LOAD] Error loading attack: {str(e)}")
            
            # Load statistics
            if 'ip_statistics' in transformed_data:
                print(f"[LOAD] Loading IP statistics")
                self._load_statistics(transformed_data['ip_statistics'])
            
            self.stats['end_time'] = datetime.now()
            duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
            
            print(f"[LOAD] Data load complete:")
            print(f"  - Packets loaded: {load_stats['packets_loaded']}")
            print(f"  - Connections loaded: {load_stats['connections_loaded']}")
            print(f"  - Attacks loaded: {load_stats['attacks_loaded']}")
            print(f"  - Errors: {load_stats['errors']}")
            print(f"  - Total duration: {duration:.2f} seconds")
            
            return load_stats
            
        except Exception as e:
            print(f"[LOAD] Error loading data: {str(e)}")
            raise
    
    def _load_batch(self, collection: str, batch: List[Dict]):
        """Load a batch of records to Firestore"""
        if not self.firestore_logger.use_firestore:
            # If Firestore is not available, save to local file
            self._save_to_local_file(collection, batch)
            return
        
        try:
            db = self.firestore_logger.db
            batch_ref = db.batch()
            
            for record in batch:
                doc_ref = db.collection(collection).document()
                batch_ref.set(doc_ref, record)
            
            batch_ref.commit()
            
        except Exception as e:
            print(f"[LOAD] Error loading batch to {collection}: {str(e)}")
            # Fallback to local file
            self._save_to_local_file(collection, batch)
    
    def _save_to_local_file(self, collection: str, data: List[Dict]):
        """Save data to local JSON file as fallback"""
        try:
            backend_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(backend_dir)
            data_dir = os.path.join(project_root, 'data', collection)
            
            os.makedirs(data_dir, exist_ok=True)
            
            filename = f"{collection}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(data_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"[LOAD] Saved {len(data)} records to {filepath}")
            
        except Exception as e:
            print(f"[LOAD] Error saving to local file: {str(e)}")
    
    def _load_statistics(self, ip_stats: Dict):
        """Load IP statistics to database"""
        try:
            if not self.firestore_logger.use_firestore:
                self._save_to_local_file('ip_statistics', [ip_stats])
                return
            
            db = self.firestore_logger.db
            stats_ref = db.collection('ip_statistics').document('latest')
            stats_ref.set({
                'timestamp': datetime.now().isoformat(),
                'statistics': ip_stats
            })
            
        except Exception as e:
            print(f"[LOAD] Error loading statistics: {str(e)}")
    
    def run(self, source: str, batch_size: int = 100) -> Dict[str, Any]:
        """
        Run complete ETL pipeline
        
        Args:
            source: Path to PCAP file or directory
            batch_size: Batch size for database loading
            
        Returns:
            Dictionary with pipeline statistics
        """
        print("=" * 60)
        print("ETL Pipeline Started")
        print("=" * 60)
        
        try:
            # Extract
            packets = self.extract(source)
            
            # Transform
            transformed_data = self.transform(packets)
            
            # Load
            load_stats = self.load(transformed_data, batch_size)
            
            # Combine statistics
            result = {
                **self.stats,
                **load_stats,
                'success': True
            }
            
            print("=" * 60)
            print("ETL Pipeline Completed Successfully")
            print("=" * 60)
            
            return result
            
        except Exception as e:
            print("=" * 60)
            print(f"ETL Pipeline Failed: {str(e)}")
            print("=" * 60)
            return {
                **self.stats,
                'success': False,
                'error': str(e)
            }


def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ETL Pipeline for Wireshark/PCAP Data')
    parser.add_argument('source', help='Path to PCAP file or directory containing PCAP files')
    parser.add_argument('--batch-size', type=int, default=100, 
                       help='Batch size for database loading (default: 100)')
    
    args = parser.parse_args()
    
    # Initialize pipeline
    pipeline = ETLPipeline()
    
    # Run pipeline
    result = pipeline.run(args.source, args.batch_size)
    
    # Print summary
    print("\n" + "=" * 60)
    print("ETL Pipeline Summary")
    print("=" * 60)
    print(f"Success: {result.get('success', False)}")
    print(f"Total Packets: {result.get('total_packets', 0)}")
    print(f"Processed Packets: {result.get('processed_packets', 0)}")
    print(f"Failed Packets: {result.get('failed_packets', 0)}")
    print(f"Connections Created: {result.get('connections_created', 0)}")
    print(f"Attacks Detected: {result.get('attacks_detected', 0)}")
    print(f"Packets Loaded: {result.get('packets_loaded', 0)}")
    print(f"Connections Loaded: {result.get('connections_loaded', 0)}")
    print(f"Attacks Loaded: {result.get('attacks_loaded', 0)}")
    
    if result.get('error'):
        print(f"Error: {result['error']}")
    
    return 0 if result.get('success') else 1


if __name__ == '__main__':
    import sys
    sys.exit(main())

