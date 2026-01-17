# Network Monitoring System - Deployment Guide

This guide provides detailed instructions for deploying the Network Monitoring System to production environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Deployment Options](#deployment-options)
3. [Production Backend Deployment](#production-backend-deployment)
4. [Frontend Deployment](#frontend-deployment)
5. [Security Configuration](#security-configuration)
6. [Monitoring and Maintenance](#monitoring-and-maintenance)
7. [Scaling Considerations](#scaling-considerations)

## Prerequisites

Before deploying to production, ensure you have:

- **Server Requirements**:
  - Minimum 2 CPU cores
  - 4GB RAM (8GB recommended)
  - 20GB storage
  - Ubuntu 20.04+ or similar Linux distribution

- **Software**:
  - Python 3.8+
  - Node.js 16+ (optional, for build tools)
  - Nginx (recommended as reverse proxy)
  - SSL/TLS certificates
  - Firewall configured

- **External Services**:
  - Gemini API key (for AI classification)
  - Firebase project (for cloud logging)
  - Monitoring solution (optional)

## Deployment Options

### Option 1: Single Server Deployment
All components on one server. Suitable for small to medium deployments.

### Option 2: Multi-Server Deployment
Separate backend and frontend servers. Better for scaling.

### Option 3: Cloud Deployment
Deploy to AWS, GCP, Azure, or similar cloud providers.

## Production Backend Deployment

### 1. Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip python3-venv -y

# Install Nginx
sudo apt install nginx -y

# Create deployment directory
sudo mkdir -p /var/www/network-monitor
cd /var/www/network-monitor
```

### 2. Application Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Clone or copy your application
# If using git:
# git clone <repository-url> .

# Install dependencies
pip install -r requirements.txt

# Install production WSGI server
pip install gunicorn
```

### 3. Configuration

Create environment configuration file:

```bash
nano /var/www/network-monitor/.env
```

Add the following:
```env
FLASK_ENV=production
SECRET_KEY=your-secret-key-here
GEMINI_API_KEY=your-gemini-api-key
GOOGLE_APPLICATION_CREDENTIALS=/path/to/firebase-credentials.json
```

### 4. Gunicorn Configuration

Create Gunicorn systemd service:

```bash
sudo nano /etc/systemd/system/network-monitor.service
```

Content:
```ini
[Unit]
Description=Network Monitor Gunicorn Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/network-monitor
Environment="PATH=/var/www/network-monitor/venv/bin"
ExecStart=/var/www/network-monitor/venv/bin/gunicorn \
    --workers 3 \
    --bind unix:network-monitor.sock \
    --timeout 120 \
    --access-logfile /var/log/network-monitor/access.log \
    --error-logfile /var/log/network-monitor/error.log \
    --log-level info \
    backend.app:app

[Install]
WantedBy=multi-user.target
```

Create log directory:
```bash
sudo mkdir -p /var/log/network-monitor
sudo chown www-data:www-data /var/log/network-monitor
```

### 5. Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Start service
sudo systemctl start network-monitor

# Enable service to start on boot
sudo systemctl enable network-monitor

# Check status
sudo systemctl status network-monitor
```

### 6. Nginx Configuration

Create Nginx configuration:

```bash
sudo nano /etc/nginx/sites-available/network-monitor
```

Content:
```nginx
upstream network_monitor_backend {
    server unix:/var/www/network-monitor/network-monitor.sock;
}

server {
    listen 80;
    server_name your-domain.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # API Routes
    location /api/ {
        proxy_pass http://network_monitor_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # File upload size
        client_max_body_size 100M;
    }

    # Frontend Static Files
    location / {
        root /var/www/network-monitor/frontend;
        try_files $uri $uri/ /index.html;
        
        # Cache static assets
        location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }

    # Deny access to sensitive files
    location ~ /\. {
        deny all;
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/network-monitor /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 7. SSL Certificate Setup

#### Using Let's Encrypt (Free):

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Obtain certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal is configured automatically
sudo certbot renew --dry-run
```

## Frontend Deployment

### Option 1: Serve via Nginx (Recommended)

```bash
# Copy frontend files to server
scp -r frontend/* user@server:/var/www/network-monitor/frontend/

# Set permissions
sudo chown -R www-data:www-data /var/www/network-monitor/frontend
```

The frontend is already configured to be served by Nginx in the configuration above.

### Option 2: Build and Deploy

If you want to optimize the frontend:

```bash
# Install build tools
npm install -g http-server

# Serve frontend
cd /var/www/network-monitor/frontend
http-server -p 8080
```

## Security Configuration

### 1. Firewall Configuration

```bash
# Configure UFW firewall
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 2. Application Security

Update `backend/app.py` for production:

```python
# Add rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Add to routes
@app.route('/api/upload-pcap', methods=['POST'])
@limiter.limit("10 per hour")
def upload_pcap():
    # ...
```

Install rate limiting:
```bash
pip install flask-limiter
```

### 3. Authentication

Add API authentication:

```python
# In app.py
from functools import wraps
import jwt

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token required'}), 401
        
        try:
            # Validate token
            jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated

# Use on protected routes
@app.route('/api/upload-pcap', methods=['POST'])
@require_auth
def upload_pcap():
    # ...
```

### 4. File Upload Security

Add file validation in `backend/packet_analyzer.py`:

```python
ALLOWED_EXTENSIONS = {'pcap'}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
```

## Monitoring and Maintenance

### 1. Log Monitoring

```bash
# View application logs
sudo journalctl -u network-monitor -f

# View Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

### 2. Health Checks

Create health check endpoint in `backend/app.py`:

```python
@app.route('/api/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })
```

### 3. Automated Backups

```bash
# Create backup script
nano /var/www/network-monitor/backup.sh
```

Content:
```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/network-monitor"

mkdir -p $BACKUP_DIR

# Backup logs
tar -czf $BACKUP_DIR/logs_$DATE.tar.gz /var/log/network-monitor/

# Keep last 7 days
find $BACKUP_DIR -name "logs_*.tar.gz" -mtime +7 -delete
```

Make executable and add to cron:
```bash
chmod +x /var/www/network-monitor/backup.sh
crontab -e
# Add: 0 2 * * * /var/www/network-monitor/backup.sh
```

### 4. Updates and Maintenance

```bash
# Update dependencies
cd /var/www/network-monitor
source venv/bin/activate
pip install --upgrade -r requirements.txt

# Restart service
sudo systemctl restart network-monitor
```

## Scaling Considerations

### 1. Horizontal Scaling

For high-traffic deployments:

1. **Load Balancer**: Use HAProxy or AWS ALB
2. **Multiple Backend Servers**: Deploy multiple instances
3. **Shared Storage**: Use S3 or NFS for file storage
4. **Database**: Use managed PostgreSQL or MongoDB

### 2. Performance Optimization

```python
# In Gunicorn configuration
--workers 4 \
--threads 2 \
--worker-class gthread \
--max-requests 1000 \
--max-requests-jitter 50
```

### 3. Caching

Add Redis for caching:

```bash
pip install redis
```

```python
# In app.py
from redis import Redis
redis = Redis(host='localhost', port=6379, db=0)

# Cache frequently accessed data
@app.route('/api/blocked-ips')
def get_blocked_ips():
    cached = redis.get('blocked_ips')
    if cached:
        return jsonify(json.loads(cached))
    
    # Get from database
    result = firewall_manager.get_blocked_ips()
    redis.setex('blocked_ips', 60, json.dumps(result))
    return jsonify(result)
```

### 4. Monitoring Tools

- **Prometheus + Grafana**: Metrics and visualization
- **ELK Stack**: Log aggregation and analysis
- **Sentry**: Error tracking
- **New Relic**: Application performance monitoring

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u network-monitor -n 50

# Check if port is in use
sudo lsof -i :5001

# Check permissions
sudo ls -la /var/www/network-monitor/
```

### Nginx 502 Bad Gateway

```bash
# Check if Gunicorn is running
sudo systemctl status network-monitor

# Check socket file
ls -la /var/www/network-monitor/network-monitor.sock

# Restart services
sudo systemctl restart network-monitor
sudo systemctl restart nginx
```

### Memory Issues

```bash
# Monitor memory usage
free -h
htop

# Increase swap space
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## Production Checklist

Before going live:

- [ ] SSL/TLS certificates configured
- [ ] Firewall rules set up
- [ ] Rate limiting enabled
- [ ] Authentication implemented
- [ ] File upload validation
- [ ] Logging configured
- [ ] Monitoring set up
- [ ] Backup strategy in place
- [ ] Disaster recovery plan
- [ ] Security audit completed
- [ ] Load testing performed
- [ ] DNS configured
- [ ] Error handling tested
- [ ] API documentation updated

---

**Version**: 1.0.0  
**Last Updated**: January 2024