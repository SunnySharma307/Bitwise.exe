from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
import requests
import json
from collections import defaultdict
from datetime import datetime
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_analyzer import PacketAnalyzer
from syn_detector import SYNDetector
from attack_classifier import AttackClassifier
from firewall_manager import FirewallManager
from firestore_logger import FirestoreLogger
from packet_capture import PacketCapture
from etl_api import etl_bp

app = Flask(__name__)
CORS(app)

# Register ETL blueprint
app.register_blueprint(etl_bp)

@app.route('/favicon.ico')
def favicon():
    """Handle favicon requests to prevent 404 errors"""
    return '', 204

# Initialize components
syn_detector = SYNDetector()
attack_classifier = AttackClassifier()
firewall_manager = FirewallManager()
firestore_logger = FirestoreLogger()
packet_analyzer = PacketAnalyzer(syn_detector, attack_classifier, firewall_manager, firestore_logger)
packet_capture = PacketCapture(output_dir='../captures')

# Real-time IP monitoring storage
ip_monitoring = defaultdict(lambda: {
    'packet_count': 0,
    'last_seen': None,
    'connections': [],
    'attack_count': 0
})

@app.route('/')
def home():
    return jsonify({
        'status': 'success',
        'message': 'Network Monitoring System API',
        'version': '1.0.0'
    })

@app.route('/api/upload-pcap', methods=['POST'])
def upload_pcap():
    """
    Upload and analyze PCAP file
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.pcap'):
            return jsonify({'error': 'File must be a .pcap file'}), 400
        
        # Save uploaded file
        filename = file.filename
        filepath = os.path.join('../uploads', filename)
        file.save(filepath)
        
        # Analyze packets
        results = packet_analyzer.analyze_pcap(filepath)
        
        return jsonify({
            'status': 'success',
            'filename': filename,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips():
    """
    Get list of currently blocked IPs
    """
    try:
        blocked_ips = firewall_manager.get_blocked_ips()
        return jsonify({
            'status': 'success',
            'blocked_ips': blocked_ips
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/unblock-ip', methods=['POST'])
def unblock_ip():
    """
    Manually unblock an IP address
    """
    try:
        data = request.get_json()
        ip_address = data.get('ip_address')
        
        if not ip_address:
            return jsonify({'error': 'IP address required'}), 400
        
        result = firewall_manager.manual_unblock(ip_address)
        
        return jsonify({
            'status': 'success',
            'message': f'IP {ip_address} unblocked',
            'result': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attack-logs', methods=['GET'])
def get_attack_logs():
    """
    Get attack logs from Firestore
    """
    try:
        limit = request.args.get('limit', 50, type=int)
        logs = firestore_logger.get_recent_logs(limit)
        
        return jsonify({
            'status': 'success',
            'logs': logs
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/clear-data', methods=['POST'])
def clear_all_data():
    """
    Clear all stored data (logs, connections, statistics)
    """
    try:
        cleared_items = []
        
        # Clear attack logs from Firestore
        if firestore_logger.use_firestore and hasattr(firestore_logger, 'db'):
            try:
                # Clear attacks collection
                attacks_ref = firestore_logger.db.collection('attacks')
                count = 0
                for doc in attacks_ref.stream():
                    doc.reference.delete()
                    count += 1
                if count > 0:
                    cleared_items.append(f"Cleared {count} attack logs from Firestore")
                
                # Clear connections collection if it exists
                try:
                    connections_ref = firestore_logger.db.collection('connections')
                    count = 0
                    for doc in connections_ref.stream():
                        doc.reference.delete()
                        count += 1
                    if count > 0:
                        cleared_items.append(f"Cleared {count} connections from Firestore")
                except:
                    pass
                
                # Clear packets collection if it exists
                try:
                    packets_ref = firestore_logger.db.collection('packets')
                    count = 0
                    for doc in packets_ref.stream():
                        doc.reference.delete()
                        count += 1
                    if count > 0:
                        cleared_items.append(f"Cleared {count} packets from Firestore")
                except:
                    pass
                
                print("[CLEAR] Cleared Firestore collections")
            except Exception as e:
                print(f"[CLEAR] Error clearing Firestore: {str(e)}")
        
        # Clear local log files
        try:
            log_file = firestore_logger.log_file
            if os.path.exists(log_file):
                with open(log_file, 'w') as f:
                    json.dump([], f)
                cleared_items.append("Cleared local log file")
                print(f"[CLEAR] Cleared local log file: {log_file}")
        except Exception as e:
            print(f"[CLEAR] Error clearing local log file: {str(e)}")
        
        # Clear in-memory data
        firestore_logger.local_logs = []
        packet_analyzer.connections = defaultdict(list)
        packet_analyzer.packet_count = 0
        packet_analyzer.attack_count = 0
        cleared_items.append("Cleared in-memory data")
        
        # Clear data directory (ETL pipeline data)
        try:
            backend_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(backend_dir)
            data_dir = os.path.join(project_root, 'data')
            if os.path.exists(data_dir):
                import shutil
                for subdir in ['packets', 'connections']:
                    subdir_path = os.path.join(data_dir, subdir)
                    if os.path.exists(subdir_path):
                        file_count = len([f for f in os.listdir(subdir_path) if f.endswith('.json')])
                        shutil.rmtree(subdir_path)
                        os.makedirs(subdir_path, exist_ok=True)
                        if file_count > 0:
                            cleared_items.append(f"Cleared {file_count} files from {subdir} directory")
                print(f"[CLEAR] Cleared data directory: {data_dir}")
        except Exception as e:
            print(f"[CLEAR] Error clearing data directory: {str(e)}")
        
        return jsonify({
            'status': 'success',
            'message': 'All data cleared successfully',
            'cleared_items': cleared_items
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attack-stats', methods=['GET'])
def get_attack_stats():
    """
    Get attack statistics
    """
    try:
        stats = firestore_logger.get_attack_statistics()
        
        return jsonify({
            'status': 'success',
            'statistics': stats
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/connection-data', methods=['GET'])
def get_connection_data():
    """
    Get connection data for visualization
    """
    try:
        connections = packet_analyzer.get_connections()
        
        return jsonify({
            'status': 'success',
            'connections': connections
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/real-time-ips', methods=['GET'])
def get_real_time_ips():
    """
    Get real-time IP monitoring data
    """
    try:
        # Update monitoring data from packet analyzer
        current_connections = packet_analyzer.get_connections()
        
        # Aggregate data by IP
        ip_data = {}
        for conn in current_connections:
            src_ip = conn['source']
            if src_ip not in ip_data:
                ip_data[src_ip] = {
                    'ip_address': src_ip,
                    'packet_count': 0,
                    'connection_count': 0,
                    'last_seen': conn['timestamp'],
                    'protocols': set(),
                    'destinations': set()
                }
            
            ip_data[src_ip]['packet_count'] += 1
            ip_data[src_ip]['connection_count'] += 1
            ip_data[src_ip]['protocols'].add(conn['protocol'])
            ip_data[src_ip]['destinations'].add(conn['destination'])
            
            # Update last seen if newer
            if conn['timestamp'] > ip_data[src_ip]['last_seen']:
                ip_data[src_ip]['last_seen'] = conn['timestamp']
        
        # Check for attacks from these IPs
        attack_logs = firestore_logger.get_recent_logs(100)
        attack_ips = {log['source_ip'] for log in attack_logs if 'source_ip' in log}
        
        # Get blocked IPs
        blocked_ips_list = firewall_manager.get_blocked_ips()
        blocked_ips_set = {block['ip_address'] for block in blocked_ips_list}
        
        # Format response
        formatted_ips = []
        for ip, data in ip_data.items():
            formatted_ips.append({
                'ip_address': ip,
                'packet_count': data['packet_count'],
                'connection_count': data['connection_count'],
                'last_seen': data['last_seen'],
                'protocols': list(data['protocols']),
                'destination_count': len(data['destinations']),
                'is_attacker': ip in attack_ips,
                'is_blocked': ip in blocked_ips_set
            })
        
        # Sort by packet count (most active first)
        formatted_ips.sort(key=lambda x: x['packet_count'], reverse=True)
        
        return jsonify({
            'status': 'success',
            'ips': formatted_ips[:50],  # Limit to top 50
            'total_ips': len(formatted_ips)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ip-geolocation', methods=['GET'])
def get_ip_geolocation():
    """
    Get geolocation data for IP addresses
    """
    try:
        ip_addresses = request.args.getlist('ips')
        if not ip_addresses:
            return jsonify({'error': 'No IP addresses provided'}), 400
        
        geolocations = []
        
        for ip in ip_addresses[:20]:  # Limit to 20 IPs per request
            try:
                # Use free ip-api.com service (no API key required for basic usage)
                response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        geolocations.append({
                            'ip': ip,
                            'country': data.get('country', 'Unknown'),
                            'region': data.get('regionName', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'lat': data.get('lat', 0),
                            'lon': data.get('lon', 0),
                            'isp': data.get('isp', 'Unknown'),
                            'timezone': data.get('timezone', 'Unknown')
                        })
                    else:
                        geolocations.append({
                            'ip': ip,
                            'error': 'Geolocation failed'
                        })
            except Exception as e:
                geolocations.append({
                    'ip': ip,
                    'error': str(e)
                })
        
        return jsonify({
            'status': 'success',
            'geolocations': geolocations
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attack-locations', methods=['GET'])
def get_attack_locations():
    """
    Get geolocation data for IPs from recent attack logs
    """
    try:
        limit = request.args.get('limit', 20, type=int)
        logs = firestore_logger.get_recent_logs(limit)
        
        # Extract unique IPs from attack logs
        unique_ips = set()
        for log in logs:
            if 'source_ip' in log:
                unique_ips.add(log['source_ip'])
        
        if not unique_ips:
            return jsonify({
                'status': 'success',
                'locations': []
            })
        
        # Get geolocation for these IPs
        geolocations = []
        for ip in list(unique_ips)[:20]:  # Limit to 20 IPs
            try:
                response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        # Count attacks from this IP
                        attack_count = sum(1 for log in logs if log.get('source_ip') == ip)
                        
                        geolocations.append({
                            'ip': ip,
                            'country': data.get('country', 'Unknown'),
                            'region': data.get('regionName', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'lat': data.get('lat', 0),
                            'lon': data.get('lon', 0),
                            'isp': data.get('isp', 'Unknown'),
                            'attack_count': attack_count
                        })
            except Exception as e:
                print(f"Error getting geolocation for {ip}: {str(e)}")
                continue
        
        return jsonify({
            'status': 'success',
            'locations': geolocations
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """
    Start live packet capture
    """
    try:
        data = request.get_json() or {}
        
        interface = data.get('interface', None)
        filter_str = data.get('filter', None)
        packet_count = data.get('packet_count', None)
        timeout = data.get('timeout', None)
        
        # Convert timeout to seconds if provided in minutes
        if timeout:
            timeout = int(timeout) * 60
        
        result = packet_capture.start_capture(
            interface=interface,
            filter=filter_str,
            packet_count=packet_count,
            timeout=timeout
        )
        
        if result['status'] == 'success':
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    """
    Stop live packet capture and save to PCAP file
    """
    try:
        data = request.get_json() or {}
        auto_analyze = data.get('auto_analyze', False)
        
        result = packet_capture.stop_capture(save_file=True)
        
        if result['status'] == 'success' and 'filepath' in result:
            # Optionally auto-analyze the captured file
            if auto_analyze:
                try:
                    analysis_results = packet_analyzer.analyze_pcap(result['filepath'])
                    result['analysis'] = analysis_results
                except Exception as e:
                    result['analysis_error'] = str(e)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/capture/status', methods=['GET'])
def get_capture_status():
    """
    Get current packet capture status
    """
    try:
        status = packet_capture.get_status()
        return jsonify({
            'status': 'success',
            'capture': status
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/capture/interfaces', methods=['GET'])
def get_interfaces():
    """
    Get list of available network interfaces
    """
    try:
        interfaces = packet_capture.get_available_interfaces()
        return jsonify({
            'status': 'success',
            'interfaces': interfaces
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/capture/analyze', methods=['POST'])
def analyze_capture():
    """
    Analyze a captured PCAP file
    """
    try:
        data = request.get_json()
        filename = data.get('filename')
        
        if not filename:
            return jsonify({'error': 'Filename required'}), 400
        
        filepath = os.path.join('../captures', filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        # Analyze the captured file
        results = packet_analyzer.analyze_pcap(filepath)
        
        return jsonify({
            'status': 'success',
            'filename': filename,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)