"""
ADVANCED NIDS with Gemini AI Mitigation
Fixed version - matches trained model features
"""

import pandas as pd
import numpy as np
import joblib
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import mitigation (will handle Gemini)
from mitigation import get_mitigation_steps

def load_model():
    """Load trained model and preprocessors"""
    try:
        model = joblib.load('models/nids_model.pkl')
        scaler = joblib.load('models/scaler.pkl')
        encoders = joblib.load('models/encoders.pkl')
        feature_names = joblib.load('models/feature_names.pkl')
        return model, scaler, encoders, feature_names
    except FileNotFoundError as e:
        print(f"❌ Model not found: {e}")
        print("Please run: python src/train_model.py first")
        return None, None, None, None

def create_feature_vector(src_ip, dst_ip, protocol, service):
    """
    Create a complete feature vector matching the trained model
    Includes all advanced features
    """
    
    # Base features
    is_attack_pattern = (service == 'private')
    
    features = {
        # Basic features
        'duration': np.random.randint(0, 100),
        'protocol_type': protocol,
        'service': service,
        'flag': 'S0' if is_attack_pattern else 'SF',
        'src_bytes': 0 if is_attack_pattern else np.random.randint(100, 5000),
        'dst_bytes': 0 if is_attack_pattern else np.random.randint(100, 5000),
        'land': 0,
        'wrong_fragment': 0,
        'urgent': 0,
        'hot': 0,
        'num_failed_logins': 5 if is_attack_pattern else 0,
        'logged_in': 0 if is_attack_pattern else 1,
        'num_compromised': 0,
        'root_shell': 0,
        'su_attempted': 0,
        'num_root': 0,
        'num_file_creations': 0,
        'num_shells': 0,
        'num_access_files': 0,
        'num_outbound_cmds': 0,
        'is_host_login': 0,
        'is_guest_login': 0,
        'count': 50 if is_attack_pattern else np.random.randint(1, 15),
        'srv_count': 50 if is_attack_pattern else np.random.randint(1, 15),
        'serror_rate': 0.5 if is_attack_pattern else 0,
        'srv_serror_rate': 0.5 if is_attack_pattern else 0,
        'rerror_rate': 0,
        'srv_rerror_rate': 0,
        'same_srv_rate': 0.1 if is_attack_pattern else 0.9,
        'diff_srv_rate': 0.9 if is_attack_pattern else 0.1,
        'srv_diff_host_rate': 0,
        'dst_host_count': 10,
        'dst_host_srv_count': 10,
        'dst_host_same_srv_rate': 0.5,
        'dst_host_diff_srv_rate': 0.5,
        'dst_host_same_src_port_rate': 0,
        'dst_host_srv_diff_host_rate': 0,
        'dst_host_serror_rate': 0,
        'dst_host_srv_serror_rate': 0,
        'dst_host_rerror_rate': 0,
        'dst_host_srv_rerror_rate': 0,
    }
    
    # Convert to DataFrame
    df = pd.DataFrame([features])
    
    # ============================================================
    # ADD ADVANCED FEATURES
    # ============================================================
    
    # Ratio Features
    df['bytes_ratio'] = df['src_bytes'] / (df['dst_bytes'] + 1)
    df['login_failure_ratio'] = df['num_failed_logins'] / (df['count'] + 1)
    df['error_rate_ratio'] = (df['serror_rate'] + 1) / (df['rerror_rate'] + 1)
    
    # Rate Features
    df['bytes_per_second'] = (df['src_bytes'] + df['dst_bytes']) / (df['duration'] + 1)
    df['connections_per_second'] = df['count'] / (df['duration'] + 1)
    df['failed_logins_per_second'] = df['num_failed_logins'] / (df['duration'] + 1)
    
    # Suspicious Binary Flags
    df['is_suspicious_flag'] = ((df['flag'] == 'S0') | (df['flag'] == 'REJ') | (df['flag'] == 'RSTR')).astype(int)
    df['is_unusual_service'] = (df['service'] == 'private').astype(int)
    df['is_zero_bytes'] = ((df['src_bytes'] == 0) & (df['dst_bytes'] == 0)).astype(int)
    df['is_unauthorized'] = (df['logged_in'] == 0).astype(int)
    df['is_land_attack'] = df['land']
    
    # Interaction Features
    df['failed_logins_x_count'] = df['num_failed_logins'] * df['count']
    df['serror_x_srv_count'] = df['serror_rate'] * df['srv_count']
    df['bytes_x_count'] = (df['src_bytes'] + df['dst_bytes']) * df['count']
    
    # Statistical Features
    df['packet_size_variance'] = np.abs(df['src_bytes'] - df['dst_bytes']) / (df['src_bytes'] + df['dst_bytes'] + 1)
    
    # Host-based features enhancement
    df['dst_host_connection_ratio'] = df['dst_host_count'] / (df['dst_host_srv_count'] + 1)
    df['dst_host_error_ratio'] = (df['dst_host_serror_rate'] + df['dst_host_rerror_rate']) / 2
    
    return df

def get_attack_type(service, count, num_failed_logins, flag):
    """Determine attack type based on features"""
    if service == 'private':
        return "Port Scan / Network Probe"
    elif num_failed_logins > 3:
        return "R2L / Brute Force Attack"
    elif count > 50:
        return "DoS Attack (Flooding)"
    elif flag == 'S0':
        return "Connection Attempt / SYN Scan"
    else:
        return "Suspicious Activity"

def get_indicators(service, flag, src_bytes, dst_bytes, logged_in, num_failed_logins, count):
    """Extract key indicators"""
    indicators = []
    if service == 'private':
        indicators.append("Connection to private/uncommon service")
    if num_failed_logins > 0:
        indicators.append(f"Multiple failed logins ({num_failed_logins})")
    if count > 30:
        indicators.append(f"High connection count ({count})")
    if src_bytes == 0 and dst_bytes == 0:
        indicators.append("Zero byte transfer (scanning behavior)")
    if logged_in == 0:
        indicators.append("Not logged in (unauthenticated access)")
    if flag == 'S0':
        indicators.append("S0 flag - connection attempt without response")
    return indicators if indicators else ["Anomalous network pattern detected"]

def analyze_connection():
    """Interactive analysis with Gemini mitigation"""
    
    print("="*60)
    print("🛡️ ADVANCED NIDS with AI-Powered Mitigation")
    print("="*60)
    
    # Get connection details
    print("\n📡 Enter Network Connection Details:")
    print("-"*40)
    src_ip = input("Source IP: ").strip()
    dst_ip = input("Destination IP: ").strip()
    protocol = input("Protocol (tcp/udp/icmp) [tcp]: ").strip() or "tcp"
    service = input("Service (http/ftp/smtp/private) [http]: ").strip() or "http"
    
    # Load model
    model, scaler, encoders, feature_names = load_model()
    if model is None:
        return
    
    # Create feature vector with all advanced features
    df = create_feature_vector(src_ip, dst_ip, protocol, service)
    
    # Encode categorical features
    categorical_cols = ['protocol_type', 'service', 'flag']
    for col in categorical_cols:
        if col in df.columns:
            try:
                df[col] = encoders[col].transform(df[col])
            except Exception as e:
                print(f"⚠️ Warning: Could not encode {col}, using 0")
                df[col] = 0
    
    # Ensure column order matches training
    if feature_names:
        # Reorder columns to match training
        for col in feature_names:
            if col not in df.columns:
                df[col] = 0
        df = df[feature_names]
    
    # Scale features
    df_scaled = scaler.transform(df)
    
    # Predict
    prob = model.predict_proba(df_scaled)[0]
    prediction = 1 if prob[1] > 0.4 else 0  # Threshold 0.4 for better detection
    confidence = prob[1] * 100 if prediction == 1 else prob[0] * 100
    
    # Get feature values for indicators
    is_attack = (service == 'private')
    src_bytes_val = 0 if is_attack else 100
    dst_bytes_val = 0 if is_attack else 100
    logged_in_val = 0 if is_attack else 1
    failed_logins_val = 5 if is_attack else 0
    count_val = 50 if is_attack else 5
    flag_val = 'S0' if is_attack else 'SF'
    
    # Display result
    print("\n" + "="*60)
    
    if prediction == 1:
        print("🔴 VERDICT: ATTACK DETECTED!")
        
        attack_type = get_attack_type(service, count_val, failed_logins_val, flag_val)
        indicators = get_indicators(service, flag_val, src_bytes_val, dst_bytes_val, 
                                    logged_in_val, failed_logins_val, count_val)
        
        print(f"⚠️  Attack Classification: {attack_type}")
        print(f"📊 Detection Confidence: {confidence:.1f}%")
        
        print(f"\n📋 Suspicious Indicators:")
        for indicator in indicators:
            print(f"   • {indicator}")
        
        # Get AI-powered mitigation
        print("\n" + "="*60)
        print("🤖 GEMINI AI - MITIGATION RECOMMENDATIONS")
        print("="*60)
        
        connection_details = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'service': service,
            'indicators': indicators
        }
        
        mitigation = get_mitigation_steps(attack_type, connection_details, confidence)
        print(mitigation)
        
        # Additional recommendations
        print("\n💡 Additional Recommendations:")
        print("   • Save this alert for security audit")
        print("   • Check logs for similar patterns")
        print("   • Update firewall rules if this persists")
        
    else:
        print("🟢 VERDICT: NORMAL TRAFFIC")
        print(f"📊 Confidence: {confidence:.1f}%")
        print("\n✅ No action needed. This connection appears legitimate.")
    
    print("\n" + "="*60)

def main():
    """Main menu"""
    while True:
        analyze_connection()
        again = input("\n🔁 Analyze another connection? (y/n): ").strip().lower()
        if again != 'y':
            print("\n👋 Exiting. Stay secure!")
            break

if __name__ == "__main__":
    main()