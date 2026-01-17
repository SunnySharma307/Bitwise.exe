# Wireshark to Database Connection Explained

## Overview

Wireshark and your database are **not directly connected**. Instead, there's an **ETL (Extract, Transform, Load) Pipeline** that acts as a bridge between them.

## Data Flow Architecture

```
┌─────────────────┐
│   Wireshark     │
│  (Local Tool)   │
└────────┬────────┘
         │
         │ Saves network packets
         │ in PCAP format
         ▼
┌─────────────────┐
│   PCAP File     │
│  (Binary Format)│
│  capture.pcap   │
└────────┬────────┘
         │
         │ ETL Pipeline reads
         │ and processes
         ▼
┌─────────────────┐
│  ETL Pipeline   │
│  (Python Script)│
│                 │
│  1. EXTRACT     │ ← Reads PCAP file
│  2. TRANSFORM   │ ← Converts to structured data
│  3. LOAD        │ ← Sends to database
└────────┬────────┘
         │
         │ Stores structured data
         ▼
┌─────────────────┐
│    Database     │
│  (Firestore/    │
│   Local JSON)   │
└─────────────────┘
```

## How It Works

### Step 1: Wireshark Captures Data

**Wireshark** is a network packet analyzer that:
- Captures network traffic in real-time
- Displays packets in a GUI
- **Saves data to PCAP files** (not to a database)

**Wireshark Storage Format:**
- **File Format**: `.pcap` or `.pcapng` (binary format)
- **Location**: Local file system (wherever you save it)
- **Content**: Raw network packets (binary data)
- **Size**: Can be very large (depends on capture duration)

**Example:**
```
Wireshark captures → Saves to → C:\Users\KOMAL\captures\network_traffic.pcap
```

### Step 2: ETL Pipeline Processes PCAP File

The **ETL Pipeline** (`etl_pipeline.py`) reads the PCAP file and processes it:

**EXTRACT Phase:**
```python
# Reads binary PCAP file
packets = rdpcap('capture.pcap')  # Uses Scapy library
# Result: List of raw packet objects
```

**TRANSFORM Phase:**
```python
# Converts each packet to structured data
packet_data = {
    'timestamp': '2024-01-15T10:30:45',
    'src_ip': '192.168.1.100',
    'dst_ip': '10.0.0.1',
    'protocol': 'TCP',
    'src_port': 54321,
    'dst_port': 80,
    'packet_size': 1500,
    # ... more fields
}
```

**LOAD Phase:**
```python
# Sends to database
db.collection('packets').add(packet_data)
```

### Step 3: Database Storage

The transformed data is stored in **Firebase Firestore** (or local JSON files):

**Database Structure:**
```
Firestore Database
├── packets/          (Individual packet records)
│   ├── packet_001
│   ├── packet_002
│   └── ...
├── connections/      (Connection flows)
│   ├── conn_001
│   └── ...
├── attacks/          (Detected attacks)
│   ├── attack_001
│   └── ...
└── ip_statistics/    (IP-level stats)
    └── latest
```

## Data Storage Comparison

### Wireshark Storage (PCAP File)

**Format**: Binary PCAP file
```python
# What Wireshark stores:
- Raw packet bytes
- Timestamps
- Packet headers
- Payload data
- Binary format (not human-readable)
```

**Example PCAP File:**
```
File: network_traffic.pcap
Size: 50 MB
Format: Binary
Content: Raw network packets
```

### Database Storage (Firestore/JSON)

**Format**: Structured JSON documents
```python
# What database stores:
{
  "packet_index": 0,
  "timestamp": "2024-01-15T10:30:45.123456",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "protocol": "TCP",
  "src_port": 54321,
  "dst_port": 80,
  "packet_size": 1500,
  "tcp_flags": {
    "syn": true,
    "ack": false
  }
}
```

**Example Database Collection:**
```
Collection: packets
Documents: 10,000 packet records
Format: JSON (structured, queryable)
Size: ~15 MB (more efficient than raw PCAP)
```

## Key Differences

| Aspect | Wireshark (PCAP) | Database (Firestore) |
|--------|------------------|----------------------|
| **Format** | Binary | JSON (structured) |
| **Readability** | Requires Wireshark | Human-readable |
| **Query** | Limited | Full query support |
| **Search** | Slow | Fast indexed search |
| **Storage** | Local file | Cloud/local database |
| **Access** | Single user | Multi-user, API access |
| **Analysis** | Manual in GUI | Programmatic, automated |
| **Size** | Large (raw data) | Smaller (structured) |

## How Data Flows

### Complete Workflow:

1. **Capture in Wireshark**
   ```
   User captures network traffic → Wireshark GUI
   ```

2. **Save PCAP File**
   ```
   File → Export → Save as capture.pcap
   Location: C:\Users\KOMAL\captures\capture.pcap
   ```

3. **Run ETL Pipeline**
   ```bash
   python wireshark_to_database.py capture.pcap
   ```

4. **ETL Processing**
   ```
   Extract: Read 10,000 packets from PCAP
   Transform: Convert to 10,000 JSON records
   Load: Insert into Firestore database
   ```

5. **Database Storage**
   ```
   Firestore Collections:
   - packets: 10,000 documents
   - connections: 500 documents
   - attacks: 25 documents
   ```

6. **Access via Application**
   ```
   Dashboard → API → Firestore → Display data
   ```

## Connection Methods

### Method 1: Manual Processing (Current)

```
Wireshark → Save PCAP → Run ETL Script → Database
```

**Steps:**
1. Capture in Wireshark
2. Export as PCAP file
3. Run: `python wireshark_to_database.py file.pcap`
4. Data appears in database

### Method 2: Automated Processing (Future)

```
Wireshark → Auto-export → Watch Folder → ETL Pipeline → Database
```

**Could be implemented with:**
- File watcher monitoring Wireshark export folder
- Automatic processing when new PCAP files appear
- Scheduled batch processing

### Method 3: Direct Capture (Alternative)

```
Network Interface → Packet Capture Script → ETL Pipeline → Database
```

**Bypasses Wireshark:**
- Use `packet_capture.py` to capture directly
- Process in real-time
- No PCAP file needed

## Data Storage Details

### What Gets Stored in Database

**1. Packet Records** (Individual packets)
```json
{
  "packet_index": 0,
  "timestamp": "2024-01-15T10:30:45",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "protocol": "TCP",
  "packet_size": 1500
}
```

**2. Connection Records** (Aggregated flows)
```json
{
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "protocol": "TCP",
  "packet_count": 150,
  "bytes_transferred": 225000,
  "first_seen": "2024-01-15T10:30:45",
  "last_seen": "2024-01-15T10:35:20"
}
```

**3. Attack Records** (Detected threats)
```json
{
  "attack_type": "SYN Flood",
  "source_ip": "192.168.1.100",
  "severity": "high",
  "packet_count": 25,
  "timestamp": "2024-01-15T10:30:45"
}
```

**4. Statistics** (Aggregated metrics)
```json
{
  "ip_statistics": {
    "192.168.1.100": {
      "packet_count": 1000,
      "bytes_sent": 500000,
      "protocols": ["TCP", "UDP"],
      "ports": [80, 443, 22]
    }
  }
}
```

## Storage Locations

### Wireshark Storage
```
Local File System:
C:\Users\KOMAL\captures\network_traffic.pcap
```

### Database Storage (Firestore)
```
Cloud Database:
- Project: your-firebase-project
- Collections: packets, connections, attacks
- Access: Via Firebase Console or API
```

### Database Storage (Local Fallback)
```
Local JSON Files:
network_monitoring/
├── data/
│   ├── packets/
│   │   └── packets_20240115_103045.json
│   ├── connections/
│   │   └── connections_20240115_103045.json
│   └── attacks/
│       └── (stored in logs/attack_logs.json)
```

## Why Use Database Instead of PCAP?

### Advantages of Database Storage:

1. **Queryable**: Search by IP, port, protocol, time range
   ```python
   # Find all packets from specific IP
   db.collection('packets').where('src_ip', '==', '192.168.1.100')
   ```

2. **Searchable**: Fast indexed searches
   ```python
   # Find attacks in last 24 hours
   db.collection('attacks').where('timestamp', '>', yesterday)
   ```

3. **Accessible**: API access from anywhere
   ```python
   # Access via REST API
   GET /api/attack-logs
   ```

4. **Analyzable**: Built-in aggregation and statistics
   ```python
   # Get connection statistics
   GET /api/connection-data
   ```

5. **Scalable**: Handles large datasets efficiently
   ```python
   # Millions of packets, fast queries
   ```

6. **Multi-user**: Multiple users can access simultaneously
   ```python
   # Dashboard, API, mobile app all access same data
   ```

## Example: Complete Data Journey

### Scenario: Capturing HTTP Traffic

**1. Wireshark Capture:**
```
Time: 10:30 AM
Action: Start capture on network interface
Duration: 5 minutes
Packets captured: 10,000
File saved: http_traffic.pcap (5 MB)
```

**2. ETL Processing:**
```bash
$ python wireshark_to_database.py http_traffic.pcap

[EXTRACT] Extracted 10,000 packets
[TRANSFORM] Processed 9,950 packets (50 failed)
[LOAD] Loaded 9,950 packets to database
[LOAD] Created 150 connection records
[LOAD] Detected 3 attacks
```

**3. Database Storage:**
```
Firestore:
- packets collection: 9,950 documents
- connections collection: 150 documents
- attacks collection: 3 documents
- Total size: ~2 MB (compressed, indexed)
```

**4. Application Access:**
```
Dashboard shows:
- 9,950 packets analyzed
- 150 active connections
- 3 attacks detected
- Real-time statistics
```

## Summary

**Connection Type**: **Indirect** (via ETL Pipeline)

**Data Flow**:
```
Wireshark (PCAP file) → ETL Pipeline → Database (Firestore/JSON)
```

**Storage Difference**:
- **Wireshark**: Binary PCAP files (raw packets)
- **Database**: Structured JSON documents (queryable data)

**Benefits**:
- Database allows querying, searching, and API access
- ETL Pipeline converts raw packets to structured data
- Application can display and analyze data in real-time

The ETL pipeline is the **bridge** that connects Wireshark's local file storage to your cloud/local database!

