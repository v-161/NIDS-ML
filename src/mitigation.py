"""
Gemini API Integration for Attack Mitigation Recommendations
Uses .env for secure API key management
"""

import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def setup_gemini():
    """Setup Gemini API using key from .env"""
    
    # Get API key from environment variable
    api_key = os.getenv('GEMINI_API_KEY')
    model_name = os.getenv('GEMINI_MODEL', 'gemini-2.5-flash')
    
    if not api_key:
        raise ValueError("❌ GEMINI_API_KEY not found in .env file!")
    
    # Configure Gemini
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(model_name)
    
    print(f"✅ Gemini configured with model: {model_name}")
    return model

def get_mitigation_steps(attack_type, connection_details, confidence):
    """Get mitigation recommendations from Gemini"""
    
    try:
        model = setup_gemini()
    except Exception as e:
        print(f"⚠️ Gemini setup failed: {e}")
        return get_fallback_mitigation(attack_type)
    
    prompt = f"""
    You are a cybersecurity expert. A Network Intrusion Detection System has detected an attack.
    
    Attack Details:
    - Attack Type: {attack_type}
    - Confidence: {confidence}%
    - Source IP: {connection_details.get('src_ip', 'Unknown')}
    - Destination IP: {connection_details.get('dst_ip', 'Unknown')}
    - Protocol: {connection_details.get('protocol', 'Unknown')}
    - Service: {connection_details.get('service', 'Unknown')}
    - Key Indicators: {', '.join(connection_details.get('indicators', ['Anomalous pattern detected']))}
    
    Provide a concise, actionable response with EXACTLY this format:
    
    🔴 IMMEDIATE ACTIONS:
    • [Action 1]
    • [Action 2]
    • [Action 3]
    
    🛡️ NETWORK LEVEL FIXES:
    • [Fix 1]
    • [Fix 2]
    
    📋 PREVENTION TIPS:
    • [Tip 1]
    • [Tip 2]
    
    Keep it practical and specific to this attack type.
    """
    
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"⚠️ Gemini API error: {e}")
        return get_fallback_mitigation(attack_type)

def get_fallback_mitigation(attack_type):
    """Fallback mitigation if API fails"""
    
    mitigations = {
        'Port Scan': """
🔴 IMMEDIATE ACTIONS:
• Block the source IP address immediately at firewall
• Enable rate limiting on all exposed ports
• Run netstat to identify all open ports on your system

🛡️ NETWORK LEVEL FIXES:
• Configure firewall to drop SYN packets on unused ports
• Deploy an IDS signature for port scanning detection

📋 PREVENTION TIPS:
• Conduct regular port audits and close unnecessary ports
• Implement port knocking for sensitive services
""",
        'DoS Attack': """
🔴 IMMEDIATE ACTIONS:
• Rate limit incoming traffic from the source IP
• Enable DDoS protection services (Cloudflare, AWS Shield)
• Contact your ISP for upstream filtering

🛡️ NETWORK LEVEL FIXES:
• Configure SYN cookies to prevent SYN flood attacks
• Implement load balancing across multiple servers

📋 PREVENTION TIPS:
• Use a CDN to absorb attack traffic
• Regularly test your DDoS preparedness
""",
        'R2L / Brute Force': """
🔴 IMMEDIATE ACTIONS:
• Disable the compromised user account immediately
• Block the source IP address at firewall
• Force password reset for all affected users

🛡️ NETWORK LEVEL FIXES:
• Enable fail2ban or similar auto-blocking
• Implement account lockout after failed attempts

📋 PREVENTION TIPS:
• Enforce strong password policy and MFA
• Monitor for unusual login patterns
""",
        'Suspicious Activity': """
🔴 IMMEDIATE ACTIONS:
• Isolate affected systems from the network
• Capture full packet capture for forensics
• Alert security team for investigation

🛡️ NETWORK LEVEL FIXES:
• Block suspicious IP addresses
• Update firewall rules to prevent similar patterns

📋 PREVENTION TIPS:
• Keep all systems patched and updated
• Conduct regular security awareness training
"""
    }
    
    return mitigations.get(attack_type, """
🔴 IMMEDIATE ACTIONS:
• Isolate affected systems from network
• Block source IP address
• Preserve logs for investigation

🛡️ NETWORK LEVEL FIXES:
• Update firewall rules
• Enable additional logging

📋 PREVENTION TIPS:
• Review security policies
• Conduct security audit
""")

def test_gemini_connection():
    """Test if Gemini API is working"""
    print("🔍 Testing Gemini API connection...")
    
    try:
        model = setup_gemini()
        response = model.generate_content("Say 'Gemini is working!' in one sentence.")
        print(f"✅ Gemini API connected: {response.text}")
        return True
    except Exception as e:
        print(f"❌ Gemini API test failed: {e}")
        print("\n💡 Troubleshooting:")
        print("1. Check if your API key is correct in .env file")
        print("2. Verify you have billing enabled on Google Cloud")
        print("3. Check your internet connection")
        return False

if __name__ == "__main__":
    test_gemini_connection()