from datetime import datetime, timedelta
import time

class FirewallManager:
    def __init__(self, block_duration_minutes=10):
        """
        Initialize firewall manager
        
        Args:
            block_duration_minutes: Duration in minutes to block IPs
        """
        self.block_duration = block_duration_minutes * 60  # Convert to seconds
        self.blocked_ips = {}  # IP -> {'blocked_at': timestamp, 'unblock_time': timestamp}
    
    def block_ip(self, ip_address):
        """
        Block an IP address for specified duration
        
        Args:
            ip_address: IP address to block
            
        Returns:
            dict with blocking status
        """
        current_time = time.time()
        unblock_time = current_time + self.block_duration
        
        self.blocked_ips[ip_address] = {
            'blocked_at': current_time,
            'unblock_time': unblock_time,
            'blocked_at_formatted': datetime.fromtimestamp(current_time).isoformat(),
            'unblock_time_formatted': datetime.fromtimestamp(unblock_time).isoformat()
        }
        
        print(f"[FIREWALL] Blocked IP: {ip_address} until {self.blocked_ips[ip_address]['unblock_time_formatted']}")
        
        return {
            'status': 'blocked',
            'ip_address': ip_address,
            'blocked_at': self.blocked_ips[ip_address]['blocked_at_formatted'],
            'unblock_at': self.blocked_ips[ip_address]['unblock_time_formatted'],
            'duration_minutes': self.block_duration / 60
        }
    
    def unblock_ip(self, ip_address):
        """
        Unblock an IP address
        """
        if ip_address in self.blocked_ips:
            del self.blocked_ips[ip_address]
            print(f"[FIREWALL] Unblocked IP: {ip_address}")
            return {
                'status': 'unblocked',
                'ip_address': ip_address,
                'timestamp': datetime.now().isoformat()
            }
        return {
            'status': 'not_blocked',
            'ip_address': ip_address
        }
    
    def manual_unblock(self, ip_address):
        """
        Manually unblock an IP address
        """
        return self.unblock_ip(ip_address)
    
    def is_blocked(self, ip_address):
        """
        Check if IP is currently blocked
        """
        if ip_address in self.blocked_ips:
            # Check if block has expired
            if time.time() >= self.blocked_ips[ip_address]['unblock_time']:
                # Auto-unblock expired block
                del self.blocked_ips[ip_address]
                return False
            return True
        return False
    
    def get_blocked_ips(self):
        """
        Get list of currently blocked IPs with details
        """
        current_time = time.time()
        active_blocks = []
        
        # Clean expired blocks
        expired_ips = []
        for ip_address, block_info in self.blocked_ips.items():
            if current_time >= block_info['unblock_time']:
                expired_ips.append(ip_address)
            else:
                active_blocks.append({
                    'ip_address': ip_address,
                    'blocked_at': block_info['blocked_at_formatted'],
                    'unblock_at': block_info['unblock_time_formatted'],
                    'remaining_seconds': int(block_info['unblock_time'] - current_time)
                })
        
        # Remove expired blocks
        for ip_address in expired_ips:
            del self.blocked_ips[ip_address]
        
        return active_blocks
    
    def check_and_unblock_expired(self):
        """
        Check and unblock expired blocks
        """
        current_time = time.time()
        expired_ips = []
        
        for ip_address, block_info in self.blocked_ips.items():
            if current_time >= block_info['unblock_time']:
                expired_ips.append(ip_address)
                print(f"[FIREWALL] Auto-unblocking expired IP: {ip_address}")
        
        for ip_address in expired_ips:
            del self.blocked_ips[ip_address]
        
        return len(expired_ips)