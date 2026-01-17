# ETL Pipeline Guide for Wireshark Data

This guide explains how to use the ETL (Extract, Transform, Load) pipeline to send Wireshark/PCAP data to your database.

## Overview

The ETL pipeline processes network packet data from Wireshark captures and loads it into Firebase Firestore (or local JSON files as fallback). The pipeline consists of three main stages:

1. **Extract**: Reads packets from PCAP files
2. **Transform**: Converts raw packet data into structured format
3. **Load**: Stores transformed data in the database

## Architecture

```
Wireshark/PCAP Files
        │
        ▼
   [EXTRACT]
   Read packets using Scapy
        │
        ▼
   [TRANSFORM]
   - Parse packet layers (Ethernet, IP, TCP, UDP, ICMP)
   - Extract connection information
   - Detect potential attacks
   - Aggregate statistics
        │
        ▼
   [LOAD]
   - Batch insert to Firestore
   - Store packets, connections, attacks
   - Update IP statistics
```

## Installation

The ETL pipeline uses the same dependencies as the main application:

```bash
pip install -r requirements.txt
```

Required packages:
- `scapy` - Packet parsing
- `firebase-admin` - Firestore database (optional)
- `flask` - API endpoints

## Usage

### Method 1: Command Line

Process a single PCAP file:

```bash
cd backend
python etl_pipeline.py path/to/your/capture.pcap
```

Process all PCAP files in a directory:

```bash
python etl_pipeline.py path/to/pcap/directory
```

With custom batch size:

```bash
python etl_pipeline.py path/to/capture.pcap --batch-size 50
```

### Method 2: Python API

```python
from backend.etl_pipeline import ETLPipeline
from backend.firestore_logger import FirestoreLogger

# Initialize
firestore_logger = FirestoreLogger()
pipeline = ETLPipeline(firestore_logger)

# Run pipeline
result = pipeline.run('path/to/capture.pcap', batch_size=100)

# Check results
print(f"Processed: {result['processed_packets']} packets")
print(f"Connections: {result['connections_created']}")
print(f"Attacks: {result['attacks_detected']}")
```

### Method 3: REST API

Start the Flask server:

```bash
cd backend
python app.py
```

Process PCAP file via API:

```bash
curl -X POST http://localhost:5001/api/etl/process \
  -H "Content-Type: application/json" \
  -d '{
    "source": "path/to/capture.pcap",
    "batch_size": 100
  }'
```

Validate source before processing:

```bash
curl -X POST http://localhost:5001/api/etl/validate \
  -H "Content-Type: application/json" \
  -d '{
    "source": "path/to/capture.pcap"
  }'
```

Get ETL status:

```bash
curl http://localhost:5001/api/etl/status
```

## Data Structure

### Packets Collection

Each packet is stored with the following structure:

```json
{
  "packet_index": 0,
  "timestamp": "2024-01-15T10:30:45.123456",
  "packet_size": 1500,
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "protocol": "TCP",
  "src_port": 54321,
  "dst_port": 80,
  "tcp_flags": {
    "syn": true,
    "ack": false,
    "fin": false,
    "rst": false
  },
  "src_mac": "00:11:22:33:44:55",
  "dst_mac": "aa:bb:cc:dd:ee:ff"
}
```

### Connections Collection

Connection records aggregate packet flows:

```json
{
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "protocol": "TCP",
  "packet_count": 150,
  "bytes_transferred": 225000,
  "first_seen": "2024-01-15T10:30:45.123456",
  "last_seen": "2024-01-15T10:35:20.789012",
  "src_port": 54321,
  "dst_port": 80
}
```

### Attacks Collection

Detected attacks are stored with details:

```json
{
  "attack_type": "SYN Flood",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.1",
  "severity": "high",
  "packet_count": 25,
  "timestamp": "2024-01-15T10:30:45.123456",
  "details": {
    "protocol": "TCP",
    "port": 80,
    "flags": {"syn": true}
  }
}
```

## Configuration

### Firebase Firestore Setup

1. **Set up Firebase credentials**:

```bash
export GOOGLE_APPLICATION_CREDENTIALS="path/to/firebase-credentials.json"
```

2. **Firestore will be used automatically** if credentials are available
3. **Local file fallback** is used if Firestore is not configured

### Batch Size

Adjust batch size based on your needs:

- **Small batches (50-100)**: Better for real-time processing, lower memory usage
- **Large batches (500-1000)**: Faster for bulk imports, higher memory usage

Default: 100 records per batch

## Performance Tips

1. **Process files in parallel** (if processing multiple files):
   ```python
   from concurrent.futures import ProcessPoolExecutor
   
   files = ['file1.pcap', 'file2.pcap', 'file3.pcap']
   with ProcessPoolExecutor(max_workers=4) as executor:
       results = executor.map(pipeline.run, files)
   ```

2. **Use appropriate batch sizes**:
   - Small files: batch_size=50
   - Large files: batch_size=500

3. **Monitor memory usage** for very large PCAP files

4. **Use directory processing** for multiple files:
   ```bash
   python etl_pipeline.py /path/to/pcap/directory
   ```

## Error Handling

The pipeline includes comprehensive error handling:

- **Failed packets** are logged but don't stop processing
- **Database errors** fall back to local file storage
- **Invalid files** are skipped with error messages
- **Statistics** track all errors for review

## Monitoring

Check pipeline statistics:

```python
# After running pipeline
stats = pipeline.stats
print(f"Total packets: {stats['total_packets']}")
print(f"Processed: {stats['processed_packets']}")
print(f"Failed: {stats['failed_packets']}")
print(f"Duration: {stats['end_time'] - stats['start_time']}")
```

## Integration with Wireshark

### Export from Wireshark

1. Open your capture in Wireshark
2. Go to **File → Export Specified Packets**
3. Choose **"pcap"** format
4. Save the file
5. Process with ETL pipeline

### Automated Export

You can automate PCAP export from Wireshark using command-line tools:

```bash
# Using tshark (Wireshark CLI)
tshark -r input.pcap -w output.pcap

# Then process with ETL
python etl_pipeline.py output.pcap
```

## Troubleshooting

### Issue: "No PCAP files found"

**Solution**: Ensure file has `.pcap` or `.pcapng` extension

### Issue: "Firestore not initialized"

**Solution**: 
- Check `GOOGLE_APPLICATION_CREDENTIALS` environment variable
- Verify Firebase credentials file path
- Pipeline will use local file fallback automatically

### Issue: "Memory error with large files"

**Solution**:
- Process files individually instead of directories
- Reduce batch size
- Process during off-peak hours

### Issue: "Slow processing"

**Solution**:
- Increase batch size
- Ensure Firestore connection is stable
- Check network latency to Firebase

## Example Workflow

Complete workflow from Wireshark to database:

```bash
# 1. Capture packets in Wireshark
# (Save as capture.pcap)

# 2. Process with ETL pipeline
cd backend
python etl_pipeline.py ../captures/capture.pcap

# 3. Verify data in database
# Check Firestore console or local JSON files in data/ directory

# 4. View in application
# Start Flask server and check dashboard
python app.py
```

## API Endpoints

### POST `/api/etl/process`

Process PCAP file through ETL pipeline.

**Request**:
```json
{
  "source": "path/to/file.pcap",
  "batch_size": 100
}
```

**Response**:
```json
{
  "status": "success",
  "message": "ETL pipeline completed successfully",
  "result": {
    "total_packets": 1000,
    "processed_packets": 995,
    "connections_created": 50,
    "attacks_detected": 5,
    "packets_loaded": 995,
    "connections_loaded": 50,
    "attacks_loaded": 5
  }
}
```

### POST `/api/etl/validate`

Validate if source path is valid for processing.

**Request**:
```json
{
  "source": "path/to/file.pcap"
}
```

**Response**:
```json
{
  "status": "success",
  "valid": true,
  "exists": true,
  "is_file": true,
  "is_pcap": true
}
```

### GET `/api/etl/status`

Get current ETL pipeline status and statistics.

**Response**:
```json
{
  "status": "success",
  "statistics": {
    "total_packets": 0,
    "processed_packets": 0,
    "firestore_enabled": true
  }
}
```

## Next Steps

1. **Set up Firebase credentials** for cloud storage
2. **Process your Wireshark captures** using the pipeline
3. **Monitor the dashboard** to see processed data
4. **Adjust batch sizes** based on your data volume
5. **Set up automated processing** for regular captures

## Support

For issues or questions:
- Check the troubleshooting section
- Review error logs in console output
- Verify file paths and permissions
- Ensure all dependencies are installed

