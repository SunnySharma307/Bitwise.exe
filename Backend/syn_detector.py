from collections import defaultdict
from datetime import datetime, timedelta
import time

class SYNDetector:
    def __init__(self, threshold=5, window_seconds=2):
        """
        Initialize SYN packet detector
        
        Args:
            threshold: Number of SYN packets to trigger detection
            window_seconds: Time window in seconds
        """
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.syn_packets = defaultdict(list)
        self.blocked_ips = {}  # IP -> unblock_time
    
    def check_syn_flood(self, src_ip, packet):
        """
        Check if IP is performing SYN flood attack
        
        Args:
            src_ip: Source IP address
            packet: Scapy packet object
            
        Returns:
            dict with detection results
        """
        current_time = time.time()
        
        # Clean old packets
        self._cleanup_old_packets(src_ip, current_time)
        
        # Add current packet
        self.syn_packets[src_ip].append(current_time)
        
        # Check if threshold exceeded
        packet_count = len(self.syn_packets[src_ip])
        
        if packet_count >= self.threshold:
            return {
                'is_attack': True,
                'source_ip': src_ip,
                'packet_count': packet_count,
                'window': self.window_seconds,
                'timestamp': datetime.now().isoformat()
            }
        
        return {
            'is_attack': False,
            'source_ip': src_ip,
            'packet_count': packet_count,
            'window': self.window_seconds
        }
    
    def _cleanup_old_packets(self, src_ip, current_time):
        """
        Remove packets outside the time window
        """
        window_start = current_time - self.window_seconds
        self.syn_packets[src_ip] = [
            timestamp for timestamp in self.syn_packets[src_ip]
            if timestamp >= window_start
        ]
    
    def is_blocked(self, ip_address):
        """
        Check if IP is currently blocked
        """
        if ip_address in self.blocked_ips:
            unblock_time = self.blocked_ips[ip_address]
            if time.time() < unblock_time:
                return True
            else:
                # Unblock if time has passed
                del self.blocked_ips[ip_address]
        return False
    
    def get_remaining_block_time(self, ip_address):
        """
        Get remaining block time in seconds
        """
        if ip_address in self.blocked_ips:
            unblock_time = self.blocked_ips[ip_address]
            remaining = unblock_time - time.time()
            return max(0, remaining)
        return 0
    
    def reset_detection(self, ip_address):
        """
        Reset detection state for an IP
        """
        if ip_address in self.syn_packets:
            del self.syn_packets[ip_address]