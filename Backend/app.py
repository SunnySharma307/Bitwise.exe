from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_analyzer import PacketAnalyzer
from syn_detector import SYNDetector
from attack_classifier import AttackClassifier
from firewall_manager import FirewallManager
from firestore_logger import FirestoreLogger

app = Flask(__name__)
CORS(app)

@app.route('/favicon.ico')
def favicon():
    """Handle favicon requests to prevent 404 errors"""
    return '', 204  # No Content

# Initialize components
syn_detector = SYNDetector()
attack_classifier = AttackClassifier()
firewall_manager = FirewallManager()
firestore_logger = FirestoreLogger()
packet_analyzer = PacketAnalyzer(syn_detector, attack_classifier, firewall_manager, firestore_logger)

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)