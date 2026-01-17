import json
from datetime import datetime
from collections import defaultdict
import os

class FirestoreLogger:
    def __init__(self):
        """
        Initialize Firestore logger
        
        Note: For this demo, we'll use a local file-based logger
        To use actual Firebase Firestore, you need to:
        1. Set GOOGLE_APPLICATION_CREDENTIALS environment variable
        2. Provide Firebase project credentials
        """
        self.use_firestore = self._initialize_firestore()
        self.local_logs = []
        # Use absolute path based on this file's location
        backend_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(backend_dir)
        self.log_file = os.path.join(project_root, 'logs', 'attack_logs.json')
        self._ensure_log_directory()
    
    def _initialize_firestore(self):
        """
        Initialize Firebase Firestore connection
        """
        try:
            import os
            credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
            
            if not credentials_path:
                print("Warning: GOOGLE_APPLICATION_CREDENTIALS not found")
                print("Using local file-based logging instead")
                return False
            
            from firebase_admin import credentials, initialize_app, firestore
            
            cred = credentials.Certificate(credentials_path)
            initialize_app(cred)
            self.db = firestore.client()
            
            print("Firestore initialized successfully")
            return True
            
        except Exception as e:
            print(f"Error initializing Firestore: {str(e)}")
            print("Using local file-based logging instead")
            return False
    
    def _ensure_log_directory(self):
        """
        Ensure log directory exists
        """
        log_dir = os.path.dirname(self.log_file)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
    
    def log_attack(self, attack_data):
        """
        Log attack to Firestore or local file
        
        Args:
            attack_data: dict containing attack information
        """
        try:
            # Add timestamp if not present
            if 'timestamp' not in attack_data:
                attack_data['timestamp'] = datetime.now().isoformat()
            
            if self.use_firestore:
                self._log_to_firestore(attack_data)
            else:
                self._log_to_file(attack_data)
            
            # Also store in memory for quick access
            self.local_logs.append(attack_data)
            
        except Exception as e:
            print(f"Error logging attack: {str(e)}")
    
    def _log_to_firestore(self, attack_data):
        """
        Log attack to Firestore
        """
        try:
            doc_ref = self.db.collection('attacks').document()
            doc_ref.set(attack_data)
            print(f"[FIRESTORE] Logged attack: {attack_data['attack_type']} from {attack_data['source_ip']}")
        except Exception as e:
            print(f"Error logging to Firestore: {str(e)}")
            # Fallback to local logging
            self._log_to_file(attack_data)
    
    def _log_to_file(self, attack_data):
        """
        Log attack to local JSON file
        """
        try:
            log_path = os.path.abspath(self.log_file)
            # Read existing logs
            existing_logs = []
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    try:
                        existing_logs = json.load(f)
                        if not isinstance(existing_logs, list):
                            existing_logs = []
                    except json.JSONDecodeError:
                        existing_logs = []
            
            # Add new log
            existing_logs.append(attack_data)
            
            # Write back to file
            with open(log_path, 'w') as f:
                json.dump(existing_logs, f, indent=2)
            
            print(f"[LOCAL_LOG] Logged attack: {attack_data['attack_type']} from {attack_data['source_ip']}")
            
        except Exception as e:
            print(f"Error logging to file: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def get_recent_logs(self, limit=50):
        """
        Get recent attack logs
        
        Args:
            limit: Maximum number of logs to return
            
        Returns:
            list of recent attack logs
        """
        try:
            if self.use_firestore:
                return self._get_firestore_logs(limit)
            else:
                return self._get_local_logs(limit)
        except Exception as e:
            print(f"Error getting logs: {str(e)}")
            return []
    
    def _get_firestore_logs(self, limit):
        """
        Get recent logs from Firestore
        """
        try:
            logs_ref = self.db.collection('attacks').order_by(
                'timestamp', direction='DESCENDING'
            ).limit(limit)
            
            logs = []
            for doc in logs_ref.stream():
                log_data = doc.to_dict()
                log_data['id'] = doc.id
                logs.append(log_data)
            
            return logs
            
        except Exception as e:
            print(f"Error getting Firestore logs: {str(e)}")
            return []
    
    def _get_local_logs(self, limit):
        """
        Get recent logs from local file
        """
        try:
            log_path = os.path.abspath(self.log_file)
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    logs = json.load(f)
                
                # Ensure logs is a list
                if not isinstance(logs, list):
                    logs = []
                
                # Sort by timestamp and limit
                logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                return logs[:limit]
            else:
                print(f"Log file not found at: {log_path}")
                return []
            
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON from log file: {str(e)}")
            return []
        except Exception as e:
            print(f"Error getting local logs: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_attack_statistics(self):
        """
        Get attack statistics
        """
        try:
            logs = self.get_recent_logs(1000)
            
            stats = {
                'total_attacks': len(logs),
                'attack_types': defaultdict(int),
                'top_source_ips': defaultdict(int),
                'top_destination_ips': defaultdict(int),
                'attacks_by_hour': defaultdict(int),
                'recent_attacks': []
            }
            
            for log in logs:
                # Count by attack type
                attack_type = log.get('attack_type', 'Unknown')
                stats['attack_types'][attack_type] += 1
                
                # Count by source IP
                src_ip = log.get('source_ip', 'Unknown')
                stats['top_source_ips'][src_ip] += 1
                
                # Count by destination IP
                dst_ip = log.get('destination_ip', 'Unknown')
                stats['top_destination_ips'][dst_ip] += 1
                
                # Count by hour
                timestamp = log.get('timestamp', '')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp)
                        hour = dt.hour
                        stats['attacks_by_hour'][hour] += 1
                    except:
                        pass
            
            # Get top 10 source IPs
            stats['top_source_ips'] = dict(
                sorted(stats['top_source_ips'].items(), 
                      key=lambda x: x[1], reverse=True)[:10]
            )
            
            # Get top 10 destination IPs
            stats['top_destination_ips'] = dict(
                sorted(stats['top_destination_ips'].items(), 
                      key=lambda x: x[1], reverse=True)[:10]
            )
            
            # Convert defaultdict to dict
            stats['attack_types'] = dict(stats['attack_types'])
            stats['attacks_by_hour'] = dict(stats['attacks_by_hour'])
            
            # Add recent attacks (last 10)
            stats['recent_attacks'] = logs[:10]
            
            return stats
            
        except Exception as e:
            print(f"Error calculating statistics: {str(e)}")
            return {}