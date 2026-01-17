"""
Test PCAP Generator
Creates test PCAP files with various attack patterns
"""

from scapy.all import *
import time
from datetime import datetime

def create_syn_flood_pcap(filename, num_packets=20, src_ip="192.168.1.100", dst_ip="10.0.0.1"):
    """
    Create a PCAP file with SYN flood attack pattern
    
    Args:
        filename: Output PCAP filename
        num_packets: Number of SYN packets to generate
        src_ip: Source IP address
        dst_ip: Destination IP address
    """
    print(f"Creating SYN flood test file: {filename}")
    
    packets = []
    for i in range(num_packets):
        # Create TCP SYN packet
        packet = IP(src=src_ip, dst=dst_ip) / TCP(flags="S", sport=1024+i, dport=80)
        packets.append(packet)
    
    # Save to PCAP
    wrpcap(filename, packets)
    print(f"✓ Created {num_packets} SYN packets in {filename}")
    return filename

def create_normal_traffic_pcap(filename, num_packets=50):
    """
    Create a PCAP file with normal traffic pattern
    
    Args:
        filename: Output PCAP filename
        num_packets: Number of packets to generate
    """
    print(f"Creating normal traffic test file: {filename}")
    
    packets = []
    
    # Generate normal traffic patterns
    src_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
    dst_ips = ["10.0.0.1", "10.0.0.2", "8.8.8.8"]
    
    for i in range(num_packets):
        src = src_ips[i % len(src_ips)]
        dst = dst_ips[i % len(dst_ips)]
        
        # Mix of TCP, UDP, and ICMP
        if i % 3 == 0:
            # Normal TCP traffic (not all SYN)
            flags = "S" if i % 10 == 0 else "A"  # Only occasional SYN
            packet = IP(src=src, dst=dst) / TCP(flags=flags, sport=1024+i, dport=80)
        elif i % 3 == 1:
            # UDP traffic
            packet = IP(src=src, dst=dst) / UDP(sport=1024+i, dport=53)
        else:
            # ICMP traffic
            packet = IP(src=src, dst=dst) / ICMP()
        
        packets.append(packet)
    
    wrpcap(filename, packets)
    print(f"✓ Created {num_packets} normal packets in {filename}")
    return filename

def create_udp_flood_pcap(filename, num_packets=30, src_ip="192.168.1.200", dst_ip="10.0.0.1"):
    """
    Create a PCAP file with UDP flood attack pattern
    
    Args:
        filename: Output PCAP filename
        num_packets: Number of UDP packets to generate
        src_ip: Source IP address
        dst_ip: Destination IP address
    """
    print(f"Creating UDP flood test file: {filename}")
    
    packets = []
    for i in range(num_packets):
        # Create UDP packet
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=1024+i, dport=53)
        packets.append(packet)
    
    wrpcap(filename, packets)
    print(f"✓ Created {num_packets} UDP packets in {filename}")
    return filename

def create_mixed_attack_pcap(filename):
    """
    Create a PCAP file with mixed attack patterns
    
    Args:
        filename: Output PCAP filename
    """
    print(f"Creating mixed attack test file: {filename}")
    
    packets = []
    
    # SYN flood from IP 192.168.1.100
    for i in range(10):
        packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(flags="S", sport=1024+i, dport=80)
        packets.append(packet)
    
    # UDP flood from IP 192.168.1.200
    for i in range(15):
        packet = IP(src="192.168.1.200", dst="10.0.0.1") / UDP(sport=1024+i, dport=53)
        packets.append(packet)
    
    # Normal traffic
    src_ips = ["192.168.1.10", "192.168.1.11"]
    for i in range(20):
        src = src_ips[i % len(src_ips)]
        packet = IP(src=src, dst="10.0.0.2") / TCP(flags="A", sport=1024+i, dport=443)
        packets.append(packet)
    
    wrpcap(filename, packets)
    print(f"✓ Created mixed attack file with {len(packets)} packets in {filename}")
    return filename

def main():
    """
    Generate all test PCAP files
    """
    print("=" * 60)
    print("Network Monitoring System - Test PCAP Generator")
    print("=" * 60)
    print()
    
    # Create test files directory
    import os
    test_dir = "../test_files"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
    
    # Generate test files
    print("Generating test PCAP files...\n")
    
    # Test 1: SYN flood attack
    create_syn_flood_pcap(
        os.path.join(test_dir, "syn_flood_test.pcap"),
        num_packets=10,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1"
    )
    
    # Test 2: Normal traffic
    create_normal_traffic_pcap(
        os.path.join(test_dir, "normal_traffic_test.pcap"),
        num_packets=50
    )
    
    # Test 3: UDP flood attack
    create_udp_flood_pcap(
        os.path.join(test_dir, "udp_flood_test.pcap"),
        num_packets=15,
        src_ip="192.168.1.200",
        dst_ip="10.0.0.1"
    )
    
    # Test 4: Mixed attacks
    create_mixed_attack_pcap(
        os.path.join(test_dir, "mixed_attacks_test.pcap")
    )
    
    # Test 5: Severe SYN flood (should definitely trigger detection)
    create_syn_flood_pcap(
        os.path.join(test_dir, "severe_syn_flood.pcap"),
        num_packets=20,
        src_ip="192.168.1.150",
        dst_ip="10.0.0.1"
    )
    
    print()
    print("=" * 60)
    print("Test files generated successfully!")
    print("=" * 60)
    print()
    print("Test files location:")
    print(f"  - {test_dir}/syn_flood_test.pcap")
    print(f"  - {test_dir}/normal_traffic_test.pcap")
    print(f"  - {test_dir}/udp_flood_test.pcap")
    print(f"  - {test_dir}/mixed_attacks_test.pcap")
    print(f"  - {test_dir}/severe_syn_flood.pcap")
    print()
    print("Upload these files to the dashboard to test the system.")
    print()

if __name__ == "__main__":
    main()