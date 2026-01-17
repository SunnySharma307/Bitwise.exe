"""
ETL API Endpoints for Wireshark Data Pipeline

REST API endpoints to trigger ETL pipeline operations
"""

from flask import Blueprint, request, jsonify
import os
from etl_pipeline import ETLPipeline
from firestore_logger import FirestoreLogger

etl_bp = Blueprint('etl', __name__)

# Initialize ETL pipeline
firestore_logger = FirestoreLogger()
etl_pipeline = ETLPipeline(firestore_logger)


@etl_bp.route('/api/etl/process', methods=['POST'])
def process_pcap():
    """
    Process PCAP file through ETL pipeline
    
    Request body:
    {
        "source": "path/to/file.pcap",
        "batch_size": 100
    }
    """
    try:
        data = request.get_json() or {}
        source = data.get('source')
        batch_size = data.get('batch_size', 100)
        
        if not source:
            return jsonify({
                'status': 'error',
                'message': 'Source path is required'
            }), 400
        
        # Check if source exists
        if not os.path.exists(source):
            return jsonify({
                'status': 'error',
                'message': f'Source path does not exist: {source}'
            }), 404
        
        # Run ETL pipeline
        result = etl_pipeline.run(source, batch_size)
        
        if result.get('success'):
            return jsonify({
                'status': 'success',
                'message': 'ETL pipeline completed successfully',
                'result': result
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'ETL pipeline failed',
                'error': result.get('error'),
                'result': result
            }), 500
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@etl_bp.route('/api/etl/status', methods=['GET'])
def get_etl_status():
    """
    Get ETL pipeline status and statistics
    """
    try:
        return jsonify({
            'status': 'success',
            'statistics': etl_pipeline.stats,
            'firestore_enabled': firestore_logger.use_firestore
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@etl_bp.route('/api/etl/validate', methods=['POST'])
def validate_source():
    """
    Validate if source path is valid for ETL processing
    
    Request body:
    {
        "source": "path/to/file.pcap"
    }
    """
    try:
        data = request.get_json() or {}
        source = data.get('source')
        
        if not source:
            return jsonify({
                'status': 'error',
                'message': 'Source path is required'
            }), 400
        
        # Check if path exists
        exists = os.path.exists(source)
        is_file = os.path.isfile(source) if exists else False
        is_dir = os.path.isdir(source) if exists else False
        
        # Check if it's a PCAP file
        is_pcap = False
        if is_file:
            is_pcap = source.endswith('.pcap') or source.endswith('.pcapng')
        
        # Check directory for PCAP files
        pcap_files = []
        if is_dir:
            pcap_files = [
                f for f in os.listdir(source)
                if f.endswith('.pcap') or f.endswith('.pcapng')
            ]
        
        return jsonify({
            'status': 'success',
            'valid': exists and (is_pcap or len(pcap_files) > 0),
            'exists': exists,
            'is_file': is_file,
            'is_directory': is_dir,
            'is_pcap': is_pcap,
            'pcap_files_count': len(pcap_files) if is_dir else 0,
            'pcap_files': pcap_files[:10] if is_dir else []  # Return first 10
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

