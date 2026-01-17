"""
Live Network Packet Capture Module
Captures network traffic using Scapy (similar to tcpdump)
"""

from scapy.all import sniff, wrpcap
from threading import Thread, Event
from datetime import datetime
import os
import time
from collections import defaultdict

class PacketCapture:
    def __init__(self, output_dir='../captures'):
        """
        Initialize packet capture system
        
        Args:
            output_dir: Directory to save captured PCAP files
        """
        self.output_dir = output_dir
        self.capture_thread = None
        self.stop_event = Event()
        self.is_capturing = False
        self.captured_packets = []
        self.capture_stats = {
            'start_time': None,
            'packet_count': 0,
            'bytes_captured': 0,
            'interface': None,
            'filter': None
        }
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def start_capture(self, interface=None, filter=None, packet_count=None, timeout=None):
        """
        Start capturing network packets
        
        Args:
            interface: Network interface to capture on (None = default/all interfaces)
            filter: BPF filter string (e.g., "tcp port 80", "host 192.168.1.1")
            packet_count: Maximum number of packets to capture (None = unlimited)
            timeout: Maximum time to capture in seconds (None = unlimited)
            
        Returns:
            dict with capture status
        """
        if self.is_capturing:
            return {
                'status': 'error',
                'message': 'Capture already in progress'
            }
        
        # Reset capture state
        self.stop_event.clear()
        self.captured_packets = []
        self.capture_stats = {
            'start_time': datetime.now().isoformat(),
            'packet_count': 0,
            'bytes_captured': 0,
            'interface': interface or 'default',
            'filter': filter or 'none'
        }
        
        # Start capture in separate thread
        self.is_capturing = True
        self.capture_thread = Thread(
            target=self._capture_packets,
            args=(interface, filter, packet_count, timeout),
            daemon=True
        )
        self.capture_thread.start()
        
        return {
            'status': 'success',
            'message': 'Packet capture started',
            'stats': self.capture_stats
        }
    
    def _capture_packets(self, interface, filter, packet_count, timeout):
        """
        Internal method to capture packets using Scapy
        """
        try:
            def packet_handler(packet):
                """Handle each captured packet"""
                if self.stop_event.is_set():
                    return
                
                self.captured_packets.append(packet)
                self.capture_stats['packet_count'] += 1
                self.capture_stats['bytes_captured'] += len(packet)
                
                # Stop if packet count limit reached
                if packet_count and self.capture_stats['packet_count'] >= packet_count:
                    self.stop_event.set()
            
            # Start sniffing
            sniff(
                iface=interface,
                filter=filter,
                prn=packet_handler,
                stop_filter=lambda x: self.stop_event.is_set(),
                count=packet_count if packet_count else 0
            )
            
        except Exception as e:
            print(f"Error during packet capture: {str(e)}")
            self.is_capturing = False
        finally:
            self.is_capturing = False
    
    def stop_capture(self, save_file=True):
        """
        Stop capturing packets and optionally save to PCAP file
        
        Args:
            save_file: Whether to save captured packets to a PCAP file
            
        Returns:
            dict with capture results
        """
        if not self.is_capturing:
            return {
                'status': 'error',
                'message': 'No capture in progress'
            }
        
        # Signal stop
        self.stop_event.set()
        
        # Wait for thread to finish (with timeout)
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        
        self.is_capturing = False
        
        # Calculate capture duration
        if self.capture_stats['start_time']:
            start_time = datetime.fromisoformat(self.capture_stats['start_time'])
            duration = (datetime.now() - start_time).total_seconds()
        else:
            duration = 0
        
        result = {
            'status': 'success',
            'message': 'Capture stopped',
            'stats': {
                **self.capture_stats,
                'duration_seconds': duration,
                'packets_captured': len(self.captured_packets)
            }
        }
        
        # Save to PCAP file if requested
        if save_file and self.captured_packets:
            filename = self._save_capture()
            result['filename'] = filename
            result['filepath'] = os.path.join(self.output_dir, filename)
        
        return result
    
    def _save_capture(self):
        """
        Save captured packets to PCAP file
        
        Returns:
            filename of saved PCAP file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"capture_{timestamp}.pcap"
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            wrpcap(filepath, self.captured_packets)
            print(f"Saved {len(self.captured_packets)} packets to {filepath}")
            return filename
        except Exception as e:
            print(f"Error saving capture file: {str(e)}")
            raise
    
    def get_status(self):
        """
        Get current capture status
        
        Returns:
            dict with capture status
        """
        if self.is_capturing and self.capture_stats['start_time']:
            start_time = datetime.fromisoformat(self.capture_stats['start_time'])
            duration = (datetime.now() - start_time).total_seconds()
        else:
            duration = 0
        
        return {
            'is_capturing': self.is_capturing,
            'stats': {
                **self.capture_stats,
                'duration_seconds': duration,
                'packets_captured': len(self.captured_packets)
            }
        }
    
    def get_available_interfaces(self):
        """
        Get list of available network interfaces
        
        Returns:
            list of interface names
        """
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
            # Filter out loopback and invalid interfaces
            valid_interfaces = [iface for iface in interfaces if iface and not iface.startswith('lo')]
            return valid_interfaces if valid_interfaces else interfaces
        except Exception as e:
            print(f"Error getting interfaces: {str(e)}")
            # Return common interface names as fallback
            return ['eth0', 'wlan0', 'en0', 'Wi-Fi', 'Ethernet']

