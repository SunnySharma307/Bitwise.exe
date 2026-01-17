import google.generativeai as genai
from datetime import datetime
import json

class AttackClassifier:
    def __init__(self):
        """
        Initialize attack classifier using Gemini API
        Note: You need to set GEMINI_API_KEY environment variable
        """
        self.api_key = None
        self.model = None
        self._initialize_gemini()
    
    def _initialize_gemini(self):
        """
        Initialize Gemini API client
        """
        try:
            # Try to get API key from environment
            import os
            self.api_key = os.getenv('GEMINI_API_KEY')
            
            if not self.api_key:
                print("Warning: GEMINI_API_KEY not found in environment variables")
                print("Attack classification will use default patterns")
                return
            
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-pro')
            
        except Exception as e:
            print(f"Error initializing Gemini API: {str(e)}")
            print("Attack classification will use default patterns")
    
    def classify_attack(self, attack_type, source_ip, packet):
        """
        Classify attack pattern using Gemini API
        
        Args:
            attack_type: Type of attack (SYN Flood, UDP Flood, etc.)
            source_ip: Source IP address
            packet: Scapy packet object
            
        Returns:
            dict with classification results
        """
        if not self.model:
            return self._default_classification(attack_type, source_ip)
        
        try:
            # Prepare analysis prompt
            prompt = self._create_analysis_prompt(attack_type, source_ip, packet)
            
            # Get classification from Gemini
            response = self.model.generate_content(prompt)
            classification_text = response.text
            
            # Parse the response
            return self._parse_classification(classification_text, attack_type)
            
        except Exception as e:
            print(f"Error classifying attack with Gemini: {str(e)}")
            return self._default_classification(attack_type, source_ip)
    
    def _create_analysis_prompt(self, attack_type, source_ip, packet):
        """
        Create analysis prompt for Gemini API
        """
        prompt = f"""
Analyze this network attack and provide classification:

Attack Type: {attack_type}
Source IP: {source_ip}
Timestamp: {datetime.now().isoformat()}

Please analyze and provide:
1. Attack Classification (e.g., DoS, DDoS, Port Scan, Brute Force)
2. Confidence Level (0-100)
3. Detailed Description
4. Potential Impact
5. Recommended Mitigation

Format your response as JSON:
{{
    "classification": "attack_type",
    "confidence": number,
    "description": "detailed description",
    "impact": "potential impact",
    "mitigation": "recommended actions"
}}
"""
        return prompt
    
    def _parse_classification(self, response_text, attack_type):
        """
        Parse Gemini API response
        """
        try:
            # Try to extract JSON from response
            if '{' in response_text and '}' in response_text:
                json_start = response_text.find('{')
                json_end = response_text.rfind('}') + 1
                json_str = response_text[json_start:json_end]
                
                parsed = json.loads(json_str)
                
                return {
                    'classification': parsed.get('classification', attack_type),
                    'confidence': parsed.get('confidence', 75),
                    'description': parsed.get('description', f'Detected {attack_type} attack'),
                    'impact': parsed.get('impact', 'Potential service disruption'),
                    'mitigation': parsed.get('mitigation', 'Block source IP')
                }
        except Exception as e:
            print(f"Error parsing classification: {str(e)}")
        
        return self._default_classification(attack_type, source_ip)
    
    def _default_classification(self, attack_type, source_ip):
        """
        Provide default classification when Gemini API is unavailable
        """
        classifications = {
            'SYN Flood': {
                'classification': 'Denial of Service (DoS) - SYN Flood',
                'confidence': 90,
                'description': f'SYN Flood attack detected from {source_ip}. Multiple SYN packets sent in short time window indicating TCP handshake abuse.',
                'impact': 'Server resource exhaustion, service unavailability',
                'mitigation': 'Block source IP, implement SYN cookies, rate limiting'
            },
            'UDP Flood': {
                'classification': 'Denial of Service (DoS) - UDP Flood',
                'confidence': 85,
                'description': f'UDP Flood attack detected from {source_ip}. High volume of UDP packets targeting network services.',
                'impact': 'Bandwidth exhaustion, service disruption',
                'mitigation': 'Rate limiting, firewall rules, traffic filtering'
            }
        }
        
        return classifications.get(attack_type, {
            'classification': 'Suspicious Network Activity',
            'confidence': 70,
            'description': f'Detected {attack_type} from {source_ip}',
            'impact': 'Potential security risk',
            'mitigation': 'Monitor and block if necessary'
        })