#!/usr/bin/env python3
"""
Visualize the data flow from Wireshark to Database

This script demonstrates how data flows through the ETL pipeline
"""

def print_data_flow():
    """Print a visual representation of the data flow"""
    
    print("=" * 70)
    print("WIRESHARK TO DATABASE DATA FLOW")
    print("=" * 70)
    print()
    
    print("STEP 1: WIRESHARK CAPTURE")
    print("-" * 70)
    print("""
    ┌─────────────────────────────────────┐
    │         WIRESHARK GUI               │
    │                                     │
    │  • Captures network packets         │
    │  • Displays in real-time            │
    │  • Analyzes protocols                │
    │                                     │
    │  [Capture] → [Save] → [Export]      │
    └──────────────┬──────────────────────┘
                   │
                   │ Saves to PCAP file
                   │ (Binary format)
                   ▼
    ┌─────────────────────────────────────┐
    │      PCAP FILE (Local Storage)      │
    │                                     │
    │  File: capture.pcap                 │
    │  Format: Binary                      │
    │  Size: 5-500 MB                      │
    │  Location: Local file system         │
    └─────────────────────────────────────┘
    """)
    
    print("\nSTEP 2: ETL PIPELINE PROCESSING")
    print("-" * 70)
    print("""
    ┌─────────────────────────────────────┐
    │      PCAP FILE                       │
    │      capture.pcap                    │
    └──────────────┬──────────────────────┘
                   │
                   │ ETL Pipeline reads file
                   ▼
    ┌─────────────────────────────────────┐
    │    ETL PIPELINE (Python)             │
    │                                      │
    │  ┌──────────────┐                   │
    │  │   EXTRACT    │                   │
    │  │              │                   │
    │  │ • Read PCAP  │                   │
    │  │ • Parse      │                   │
    │  │ • Extract    │                   │
    │  └──────┬───────┘                   │
    │         │                            │
    │         ▼                            │
    │  ┌──────────────┐                   │
    │  │  TRANSFORM   │                   │
    │  │              │                   │
    │  │ • Structure  │                   │
    │  │ • Parse      │                   │
    │  │ • Aggregate  │                   │
    │  │ • Detect     │                   │
    │  └──────┬───────┘                   │
    │         │                            │
    │         ▼                            │
    │  ┌──────────────┐                   │
    │  │    LOAD      │                   │
    │  │              │                   │
    │  │ • Batch      │                   │
    │  │ • Insert     │                   │
    │  │ • Index      │                   │
    │  └──────┬───────┘                   │
    └─────────┼────────────────────────────┘
              │
              │ Sends structured data
              ▼
    """)
    
    print("\nSTEP 3: DATABASE STORAGE")
    print("-" * 70)
    print("""
    ┌─────────────────────────────────────┐
    │    DATABASE (Firestore/JSON)        │
    │                                     │
    │  Collections:                       │
    │  ┌─────────────────────────────┐   │
    │  │ packets/                     │   │
    │  │  ├── packet_001              │   │
    │  │  ├── packet_002              │   │
    │  │  └── ... (10,000 records)    │   │
    │  └─────────────────────────────┘   │
    │                                     │
    │  ┌─────────────────────────────┐   │
    │  │ connections/                 │   │
    │  │  ├── conn_001                │   │
    │  │  └── ... (150 records)       │   │
    │  └─────────────────────────────┘   │
    │                                     │
    │  ┌─────────────────────────────┐   │
    │  │ attacks/                     │   │
    │  │  ├── attack_001              │   │
    │  │  └── ... (3 records)         │   │
    │  └─────────────────────────────┘   │
    │                                     │
    │  Format: JSON (structured)          │
    │  Queryable: Yes                     │
    │  Searchable: Yes                    │
    └──────────────┬──────────────────────┘
                   │
                   │ API Access
                   ▼
    ┌─────────────────────────────────────┐
    │    WEB APPLICATION                  │
    │                                     │
    │  • Dashboard                        │
    │  • Real-time stats                  │
    │  • Attack logs                      │
    │  • Connection maps                  │
    └─────────────────────────────────────┘
    """)
    
    print("\n" + "=" * 70)
    print("DATA TRANSFORMATION EXAMPLE")
    print("=" * 70)
    print()
    
    print("BEFORE (PCAP - Binary):")
    print("-" * 70)
    print("""
    Raw binary data (not human-readable):
    
    0000  00 11 22 33 44 55 aa bb cc dd ee ff 08 00 45 00
    0010  00 3c 1c 46 40 00 40 06 b1 e6 c0 a8 01 64 c0 a8
    0020  01 01 30 39 00 50 00 00 00 00 00 00 00 00 50 02
    0030  20 00 91 7c 00 00 00 00 00 00 00 00
    """)
    
    print("\nAFTER (Database - JSON):")
    print("-" * 70)
    print("""
    Structured JSON (human-readable, queryable):
    
    {
      "packet_index": 0,
      "timestamp": "2024-01-15T10:30:45.123456",
      "src_ip": "192.168.1.100",
      "dst_ip": "192.168.1.1",
      "protocol": "TCP",
      "src_port": 12345,
      "dst_port": 80,
      "packet_size": 60,
      "tcp_flags": {
        "syn": true,
        "ack": false
      },
      "src_mac": "00:11:22:33:44:55",
      "dst_mac": "aa:bb:cc:dd:ee:ff"
    }
    """)
    
    print("\n" + "=" * 70)
    print("STORAGE COMPARISON")
    print("=" * 70)
    print()
    
    comparison = [
        ["Aspect", "Wireshark (PCAP)", "Database (Firestore)"],
        ["Format", "Binary", "JSON"],
        ["Readability", "Requires Wireshark", "Human-readable"],
        ["Query", "Limited", "Full SQL-like queries"],
        ["Search", "Slow (file scan)", "Fast (indexed)"],
        ["Storage", "Local file", "Cloud/Local"],
        ["Access", "Single user", "Multi-user, API"],
        ["Size (10k packets)", "~5 MB", "~2 MB (compressed)"],
        ["Analysis", "Manual GUI", "Programmatic"],
    ]
    
    # Print table
    col_widths = [20, 25, 25]
    for row in comparison:
        print(" | ".join(str(cell).ljust(width) for cell, width in zip(row, col_widths)))
        if row == comparison[0]:
            print("-" * 70)
    
    print("\n" + "=" * 70)
    print("KEY TAKEAWAY")
    print("=" * 70)
    print("""
    Wireshark and Database are NOT directly connected.
    
    The connection is made through:
    
    1. Wireshark saves PCAP files (local storage)
    2. ETL Pipeline reads PCAP files
    3. ETL Pipeline transforms data to structured format
    4. ETL Pipeline loads data into database
    5. Application accesses database via API
    
    This allows:
    • Querying packet data
    • Searching by IP, port, protocol
    • Real-time dashboard updates
    • Multi-user access
    • Automated analysis
    """)
    
    print("=" * 70)


if __name__ == '__main__':
    print_data_flow()

