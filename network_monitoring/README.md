# Network Monitoring System

An intelligent network monitoring system that analyzes traffic patterns, detects abnormal request behavior, logs suspicious activity in real-time, classifies attack patterns using AI, and visualizes attack sources on Google Maps.

## Features

### 🔍 Traffic Analysis
- **PCAP File Upload**: Upload network capture files for comprehensive analysis
- **Packet Parsing**: Extract and analyze TCP, UDP, and ICMP packets
- **Connection Tracking**: Monitor source-destination relationships

### 🛡️ Attack Detection
- **SYN Flood Detection**: Identify IPs sending more than 5 SYN packets in 2 seconds
- **UDP Flood Detection**: Detect high-volume UDP packet bursts
- **Real-time Alerts**: Immediate notification of suspicious activities

### 🤖 AI-Powered Classification
- **Gemini API Integration**: Automatic attack pattern classification
- **Confidence Scoring**: Machine learning-based threat assessment
- **Detailed Analysis**: Comprehensive attack descriptions and mitigation recommendations

### 🔥 Firewall Management
- **Automatic IP Blocking**: Block malicious IPs for 10 minutes
- **Auto-Unblock**: Automatically remove blocks after timeout
- **Manual Override**: Administrator can manually unblock IPs

### 📊 Visualization & Logging
- **Google Maps Integration**: Geographic visualization of attack sources
- **Real-time Dashboard**: Live statistics and monitoring
- **Attack Logs**: Detailed Firebase Firestore logging
- **Connection Maps**: Visual representation of network traffic

## System Architecture

```
┌─────────────────┐
│   Frontend      │
│  (HTML/CSS/JS)  │
└────────┬────────┘
         │
         │ HTTP/REST API
         │
┌────────▼────────┐
│   Backend API   │
│   (Flask)       │
└────────┬────────┘
         │
    ┌────┴────┬──────────┬──────────┐
    │         │          │          │
┌───▼───┐ ┌──▼───┐  ┌──▼────┐ ┌──▼────────┐
│Packet │ │ SYN  │  │Gemini │ │ Firestore │
│Analyzer│ │Detector│  │ API   │ │  Logger   │
└───┬───┘ └──┬───┘  └───┬───┘ └───────────┘
    │         │           │
    │         │           │
┌───▼─────────▼───────────▼────────┐
│     Firewall Manager              │
│  (Block/Unblock IPs)              │
└───────────────────────────────────┘
```

## Installation

### Prerequisites
- Python 3.8+
- Node.js (for frontend development)
- Google Gemini API Key (optional, for AI classification)
- Firebase credentials (optional, for cloud logging)

### Backend Setup

1. **Navigate to backend directory:**
```bash
cd network_monitoring/backend
```

2. **Install Python dependencies:**
```bash
pip install -r ../requirements.txt
```

3. **Set up environment variables (optional):**
```bash
export GEMINI_API_KEY='your_gemini_api_key'
export GOOGLE_APPLICATION_CREDENTIALS='path/to/firebase_credentials.json'
```

4. **Start the Flask server:**
```bash
python app.py
```

The backend API will be available at `http://localhost:5000`

### Frontend Setup

1. **Navigate to frontend directory:**
```bash
cd network_monitoring/frontend
```

2. **Start a web server:**
```bash
# Using Python
python -m http.server 8080

# Or using Node.js
npx http-server -p 8080
```

3. **Open browser:**
Navigate to `http://localhost:8080`

## Usage Guide

### 1. Upload PCAP File

1. Click on the "Upload PCAP" section
2. Drag and drop your `.pcap` file or click to browse
3. The system will automatically:
   - Analyze all packets
   - Detect SYN flood attacks (5+ SYN packets in 2 seconds)
   - Block malicious IPs
   - Log attacks to Firebase
   - Classify attack patterns

### 2. Monitor Dashboard

- **Total Packets**: Number of packets analyzed
- **Attacks Detected**: Count of detected attacks
- **Blocked IPs**: Number of currently blocked IP addresses
- **Active Connections**: Active network connections

### 3. View Attack Logs

- Scroll through recent attack logs
- View attack types, timestamps, and details
- See AI classification and confidence scores
- Review source and destination IPs

### 4. Manage Blocked IPs

- View all currently blocked IPs
- See remaining block time
- Manually unblock IPs if needed
- Auto-unblock after 10 minutes

### 5. Geographic Visualization

- View attack sources on Google Maps
- Identify geographic patterns
- Correlate attacks with locations

## API Endpoints

### POST `/api/upload-pcap`
Upload and analyze PCAP file

**Request:**
- Method: POST
- Content-Type: multipart/form-data
- Body: file (pcap file)

**Response:**
```json
{
  "status": "success",
  "filename": "capture.pcap",
  "results": {
    "total_packets": 1000,
    "analyzed_packets": 950,
    "attacks_detected": 3,
    "blocked_ips": ["192.168.1.100"],
    "connections": [...],
    "attack_types": {"SYN Flood": 2, "UDP Flood": 1}
  }
}
```

### GET `/api/blocked-ips`
Get list of currently blocked IPs

**Response:**
```json
{
  "status": "success",
  "blocked_ips": [
    {
      "ip_address": "192.168.1.100",
      "blocked_at": "2024-01-15T10:30:00",
      "unblock_at": "2024-01-15T10:40:00",
      "remaining_seconds": 300
    }
  ]
}
```

### POST `/api/unblock-ip`
Manually unblock an IP address

**Request:**
```json
{
  "ip_address": "192.168.1.100"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "IP 192.168.1.100 unblocked"
}
```

### GET `/api/attack-logs`
Get recent attack logs

**Parameters:**
- limit (optional): Number of logs to return (default: 50)

**Response:**
```json
{
  "status": "success",
  "logs": [
    {
      "timestamp": "2024-01-15T10:30:00",
      "attack_type": "SYN Flood",
      "source_ip": "192.168.1.100",
      "destination_ip": "10.0.0.1",
      "classification": "Denial of Service",
      "confidence": 90
    }
  ]
}
```

### GET `/api/attack-stats`
Get attack statistics

**Response:**
```json
{
  "status": "success",
  "statistics": {
    "total_attacks": 150,
    "attack_types": {
      "SYN Flood": 100,
      "UDP Flood": 50
    },
    "top_source_ips": {...},
    "attacks_by_hour": {...}
  }
}
```

### GET `/api/connection-data`
Get connection data for visualization

**Response:**
```json
{
  "status": "success",
  "connections": [
    {
      "source": "192.168.1.100",
      "destination": "10.0.0.1",
      "timestamp": "2024-01-15T10:30:00",
      "protocol": "TCP"
    }
  ]
}
```

## Detection Rules

### SYN Flood Detection
- **Threshold**: 5 SYN packets
- **Time Window**: 2 seconds
- **Action**: Block IP for 10 minutes
- **Auto-unblock**: Yes

### UDP Flood Detection
- **Threshold**: 10 UDP packets
- **Action**: Log and classify attack
- **Classification**: Denial of Service

## Configuration

### Modify Detection Thresholds

Edit `network_monitoring/backend/syn_detector.py`:

```python
# Change these values
threshold = 5  # Number of SYN packets
window_seconds = 2  # Time window in seconds
```

### Change Block Duration

Edit `network_monitoring/backend/firewall_manager.py`:

```python
block_duration_minutes = 10  # Duration in minutes
```

## Troubleshooting

### Issue: Backend not starting
**Solution**: Ensure all dependencies are installed:
```bash
pip install -r requirements.txt
```

### Issue: Frontend cannot connect to backend
**Solution**: 
1. Ensure backend is running on port 5000
2. Check CORS settings in app.py
3. Verify API_BASE_URL in frontend/js/script.js

### Issue: Gemini API not working
**Solution**:
1. Set GEMINI_API_KEY environment variable
2. Verify API key is valid
3. Check internet connection

### Issue: PCAP file not uploading
**Solution**:
1. Ensure file is in .pcap format
2. Check file size (large files may timeout)
3. Verify uploads directory exists

## Security Considerations

- **API Keys**: Never commit API keys to version control
- **Firewall Rules**: Ensure proper firewall rules on host system
- **Rate Limiting**: Implement rate limiting on API endpoints
- **Authentication**: Add authentication for production use
- **Data Privacy**: Ensure proper handling of sensitive network data

## Future Enhancements

- [ ] Real-time traffic monitoring (live packet capture)
- [ ] Machine learning model training for custom attack patterns
- [ ] Email/SMS alerts for detected attacks
- [ ] Integration with SIEM systems
- [ ] Support for more attack types (HTTP flood, DNS amplification, etc.)
- [ ] Mobile app for monitoring on-the-go
- [ ] Advanced analytics and reporting

## Technologies Used

### Backend
- **Flask**: Web framework
- **Scapy**: Packet manipulation
- **Google Generative AI**: Attack classification
- **Firebase Admin SDK**: Cloud logging

### Frontend
- **HTML5/CSS3**: Modern responsive design
- **JavaScript**: Client-side logic
- **Google Maps**: Geographic visualization
- **Font Awesome**: Icons

## License

This project is for educational and research purposes.

## Support

For issues, questions, or contributions, please refer to the project documentation or contact the development team.

---

**Version**: 1.0.0  
**Last Updated**: January 2024