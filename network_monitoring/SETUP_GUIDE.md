# Network Monitoring System - Setup Guide

This guide will help you set up and run the Network Monitoring System from scratch.

## Quick Start

### Step 1: Install Dependencies

```bash
# Navigate to project directory
cd network_monitoring

# Install Python dependencies
pip install -r requirements.txt
```

### Step 2: Start Backend Server

```bash
# Navigate to backend directory
cd backend

# Start Flask server
python app.py
```

The backend will start on `http://localhost:5000`

### Step 3: Start Frontend

```bash
# Open a new terminal and navigate to frontend directory
cd network_monitoring/frontend

# Start a web server (choose one option)
# Option 1: Python
python -m http.server 8080

# Option 2: Node.js (if installed)
npx http-server -p 8080
```

The frontend will be available at `http://localhost:8080`

### Step 4: Access the Dashboard

Open your browser and navigate to:
```
http://localhost:8080
```

## Detailed Setup Instructions

### Prerequisites Check

Before starting, ensure you have:

- Python 3.8 or higher
- pip (Python package manager)
- A modern web browser (Chrome, Firefox, Edge)

```bash
# Check Python version
python --version

# Check pip version
pip --version
```

### Backend Setup

#### 1. Install Python Dependencies

The `requirements.txt` file includes all necessary packages:

- `scapy` - Packet manipulation
- `flask` - Web framework
- `flask-cors` - CORS support
- `google-generativeai` - Gemini AI API
- `firebase-admin` - Firebase integration
- `pyshark` - Network packet analysis
- `ipaddress` - IP address manipulation

```bash
pip install -r requirements.txt
```

#### 2. Optional: Configure AI and Cloud Services

For enhanced features, you can configure:

**Gemini API (for AI-powered attack classification):**

```bash
# Linux/Mac
export GEMINI_API_KEY='your_api_key_here'

# Windows (PowerShell)
$env:GEMINI_API_KEY='your_api_key_here'

# Windows (Command Prompt)
set GEMINI_API_KEY=your_api_key_here
```

**Firebase (for cloud logging):**

1. Create a Firebase project at console.firebase.google.com
2. Download service account credentials JSON
3. Set environment variable:

```bash
export GOOGLE_APPLICATION_CREDENTIALS='path/to/your/firebase_credentials.json'
```

#### 3. Start the Backend

```bash
cd network_monitoring/backend
python app.py
```

You should see:
```
 * Running on http://0.0.0.0:5000
 * Running on http://127.0.0.1:5000
```

#### 4. Verify Backend is Running

Test the API endpoint:
```bash
curl http://localhost:5000/
```

Expected response:
```json
{
  "status": "success",
  "message": "Network Monitoring System API",
  "version": "1.0.0"
}
```

### Frontend Setup

#### 1. Choose a Web Server

**Option A: Python HTTP Server**

```bash
cd network_monitoring/frontend
python -m http.server 8080
```

**Option B: Node.js HTTP Server**

```bash
# Install http-server globally (first time only)
npm install -g http-server

# Start server
cd network_monitoring/frontend
http-server -p 8080
```

**Option C: VS Code Live Server**

If using VS Code:
1. Install "Live Server" extension
2. Right-click on `index.html`
3. Select "Open with Live Server"

#### 2. Access the Dashboard

Open your browser and navigate to:
```
http://localhost:8080
```

## Testing the System

### 1. Create a Test PCAP File

If you don't have a PCAP file, you can create a simple one using Python:

```python
from scapy.all import *

# Create packets
packets = []
for i in range(20):
    packet = IP(src="192.168.1.100", dst="10.0.0.1")/TCP(flags="S", sport=1024+i)
    packets.append(packet)

# Save to PCAP
wrpcap("test_syn_flood.pcap", packets)
print("Created test_syn_flood.pcap")
```

### 2. Upload and Analyze

1. Open the dashboard in your browser
2. Navigate to "Upload PCAP" section
3. Upload your PCAP file
4. View the analysis results

### 3. Check Detection Results

After upload, you should see:
- Packet analysis statistics
- Detected attacks (if any)
- Blocked IP addresses
- Attack classification (if Gemini API is configured)

## Configuration

### Modify Detection Thresholds

Edit `network_monitoring/backend/syn_detector.py`:

```python
class SYNDetector:
    def __init__(self, threshold=5, window_seconds=2):
        # Change threshold to detect more/less aggressive attacks
        # Change window_seconds to adjust time sensitivity
```

### Change Block Duration

Edit `network_monitoring/backend/firewall_manager.py`:

```python
class FirewallManager:
    def __init__(self, block_duration_minutes=10):
        # Change block_duration_minutes to adjust blocking time
```

### Update API Endpoint

If you need to change the backend URL, edit `network_monitoring/frontend/js/script.js`:

```javascript
const API_BASE_URL = 'http://localhost:5000/api';
```

## Troubleshooting

### Issue: Backend won't start

**Error:** `ModuleNotFoundError: No module named 'scapy'`

**Solution:**
```bash
pip install -r requirements.txt
```

### Issue: Frontend can't connect to backend

**Error:** `Failed to fetch` in browser console

**Solutions:**
1. Ensure backend is running on port 5000
2. Check that CORS is enabled (it is by default in app.py)
3. Verify API_BASE_URL in script.js matches backend URL
4. Check firewall settings

### Issue: PCAP upload fails

**Error:** `File must be a .pcap file`

**Solution:**
- Ensure file extension is exactly `.pcap`
- Check file size (large files may timeout)
- Verify file is a valid pcap format

### Issue: No attacks detected

**Solution:**
- Verify your PCAP contains TCP SYN packets
- Check detection thresholds in syn_detector.py
- Ensure packets are within the time window
- View console logs for debugging information

### Issue: Google Maps not displaying

**Solution:**
- Check internet connection
- Verify the embed URL is correct
- Ensure browser allows iframes

## Production Deployment

### Backend Deployment

For production deployment:

1. Use a production WSGI server (e.g., Gunicorn):
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

2. Set up reverse proxy (Nginx):
```nginx
location /api/ {
    proxy_pass http://localhost:5000/api/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

3. Enable HTTPS
4. Set up proper authentication
5. Configure firewall rules

### Frontend Deployment

For production deployment:

1. Build optimized assets (if using build tools)
2. Deploy to static hosting (e.g., AWS S3, Netlify, Vercel)
3. Configure CDN for static assets
4. Enable HTTPS
5. Set up caching policies

## Security Best Practices

1. **Never commit API keys** to version control
2. **Use environment variables** for sensitive configuration
3. **Implement authentication** for API endpoints
4. **Enable HTTPS** in production
5. **Set up rate limiting** on API endpoints
6. **Regularly update dependencies**
7. **Monitor system logs** for suspicious activity
8. **Implement proper input validation**

## Next Steps

1. **Configure AI Services**: Set up Gemini API for enhanced attack classification
2. **Set up Firebase**: Enable cloud logging for persistent attack logs
3. **Create Test Data**: Generate various attack scenarios for testing
4. **Customize Detection**: Adjust thresholds based on your network patterns
5. **Set up Monitoring**: Configure alerts for system health
6. **Scale Deployment**: Plan for high-traffic scenarios

## Support and Resources

- **Documentation**: See `README.md` for detailed feature documentation
- **API Reference**: See `README.md` API Endpoints section
- **Troubleshooting**: Check the Troubleshooting section above
- **Community**: Join our community for support and discussions

---

**Version**: 1.0.0  
**Last Updated**: January 2024