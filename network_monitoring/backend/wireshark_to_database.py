#!/usr/bin/env python3
"""
Simple script to process Wireshark PCAP files and send to database

Usage:
    python wireshark_to_database.py <pcap_file>
    python wireshark_to_database.py <pcap_directory>
"""

import sys
import os
from etl_pipeline import ETLPipeline
from firestore_logger import FirestoreLogger

def main():
    if len(sys.argv) < 2:
        print("Usage: python wireshark_to_database.py <pcap_file_or_directory>")
        print("\nExamples:")
        print("  python wireshark_to_database.py capture.pcap")
        print("  python wireshark_to_database.py /path/to/pcap/files/")
        sys.exit(1)
    
    source = sys.argv[1]
    
    if not os.path.exists(source):
        print(f"Error: Path does not exist: {source}")
        sys.exit(1)
    
    print("=" * 60)
    print("Wireshark to Database ETL Pipeline")
    print("=" * 60)
    print(f"Source: {source}")
    print()
    
    # Initialize pipeline
    print("Initializing ETL pipeline...")
    firestore_logger = FirestoreLogger()
    pipeline = ETLPipeline(firestore_logger)
    
    if firestore_logger.use_firestore:
        print("✓ Firebase Firestore enabled")
    else:
        print("⚠ Using local file storage (Firestore not configured)")
        print("  Set GOOGLE_APPLICATION_CREDENTIALS to enable Firestore")
    print()
    
    # Run pipeline
    try:
        result = pipeline.run(source, batch_size=100)
        
        if result.get('success'):
            print()
            print("=" * 60)
            print("✓ ETL Pipeline Completed Successfully!")
            print("=" * 60)
            print(f"Total Packets: {result.get('total_packets', 0)}")
            print(f"Processed: {result.get('processed_packets', 0)}")
            print(f"Failed: {result.get('failed_packets', 0)}")
            print(f"Connections: {result.get('connections_created', 0)}")
            print(f"Attacks Detected: {result.get('attacks_detected', 0)}")
            print(f"Packets Loaded: {result.get('packets_loaded', 0)}")
            print(f"Connections Loaded: {result.get('connections_loaded', 0)}")
            print(f"Attacks Loaded: {result.get('attacks_loaded', 0)}")
            
            if result.get('end_time') and result.get('start_time'):
                duration = (result['end_time'] - result['start_time']).total_seconds()
                print(f"Duration: {duration:.2f} seconds")
            
            print()
            print("Data has been loaded to database!")
            print("You can now view it in the Network Monitor dashboard.")
            
            sys.exit(0)
        else:
            print()
            print("=" * 60)
            print("✗ ETL Pipeline Failed")
            print("=" * 60)
            print(f"Error: {result.get('error', 'Unknown error')}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\nPipeline interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()

