"""
Test NIDS with IP-based network traffic simulation
Simulates network connections with source/destination IPs
"""

import pandas as pd
import numpy as np
import joblib
import random
from datetime import datetime

def load_model():
    """Load the trained model"""
    try:
        model = joblib.load('models/nids_model.pkl')
        scaler = joblib.load('models/scaler.pkl')
        encoders = joblib.load('models/encoders.pkl')
        return model, scaler, encoders
    except:
        print("❌ Model not found! Run: python src/train_model.py")
        return None, None, None

def ip_to_features(src_ip, dst_ip, protocol='tcp', service='http'):
    """Convert IP addresses to network features"""
    
    # Simple IP to numeric conversion (last octet)
    src_last_octet = int(src_ip.split('.')[-1]) if '.' in src_ip else 0
    dst_last_octet = int(dst_ip.split('.')[-1]) if '.' in dst_ip else 0
    
    # Determine if it's internal/external traffic
    is_internal = src_ip.startswith(('192.168.', '10.', '172.16.'))
    
    # Generate features based on IPs
    features = {
        'duration': random.randint(0, 100),
        'protocol_type': protocol,
        'service': service,
        'flag': 'SF',  # Normal flag by default
        'src_bytes': random.randint(0, 5000),
        'dst_bytes': random.randint(0, 5000),
        'land': 1 if src_ip == dst_ip else 0,
        'wrong_fragment': 0,
        'urgent': 0,
        'hot': 0,
        'num_failed_logins': 0,
        'logged_in': 1 if is_internal else 0,
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
        'count': random.randint(1, 10),
        'srv_count': random.randint(1, 10),
        'serror_rate': random.random() * 0.1,
        'srv_serror_rate': random.random() * 0.1,
        'rerror_rate': random.random() * 0.1,
        'srv_rerror_rate': random.random() * 0.1,
        'same_srv_rate': random.random(),
        'diff_srv_rate': random.random(),
        'srv_diff_host_rate': random.random(),
        'dst_host_count': random.randint(1, 100),
        'dst_host_srv_count': random.randint(1, 10),
        'dst_host_same_srv_rate': random.random(),
        'dst_host_diff_srv_rate': random.random(),
        'dst_host_same_src_port_rate': random.random(),
        'dst_host_srv_diff_host_rate': random.random(),
        'dst_host_serror_rate': random.random(),
        'dst_host_srv_serror_rate': random.random(),
        'dst_host_rerror_rate': random.random(),
        'dst_host_srv_rerror_rate': random.random()
    }
    
    return features

def predict_traffic(src_ip, dst_ip, protocol, service, model, scaler, encoders):
    """Predict if traffic between IPs is normal or attack"""
    
    # Generate features from IPs
    features = ip_to_features(src_ip, dst_ip, protocol, service)
    
    # Convert to DataFrame
    df = pd.DataFrame([features])
    
    # Encode categorical features
    categorical_cols = ['protocol_type', 'service', 'flag']
    for col in categorical_cols:
        if col in df.columns:
            try:
                df[col] = encoders[col].transform(df[col])
            except:
                # Use default value if unknown
                df[col] = 0
    
    # Scale features
    df_scaled = scaler.transform(df)
    
    # Predict
    prediction = model.predict(df_scaled)[0]
    probabilities = model.predict_proba(df_scaled)[0]
    
    return prediction, probabilities, features

def analyze_traffic(src_ip, dst_ip, protocol='tcp', service='http'):
    """Analyze traffic between two IPs"""
    
    # Load model
    model, scaler, encoders = load_model()
    if model is None:
        return
    
    print("\n" + "="*60)
    print("🌐 NETWORK TRAFFIC ANALYSIS")
    print("="*60)
    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {dst_ip}")
    print(f"Protocol: {protocol}")
    print(f"Service: {service}")
    print("-"*60)
    
    # Make prediction
    prediction, probabilities, features = predict_traffic(
        src_ip, dst_ip, protocol, service, model, scaler, encoders
    )
    
    # Display result
    if prediction == 1:
        print("\n🔴 VERDICT: MALICIOUS TRAFFIC DETECTED!")
        print("⚠️  This connection shows attack patterns!")
    else:
        print("\n🟢 VERDICT: NORMAL TRAFFIC")
        print("✅ This connection appears legitimate!")
    
    print(f"\n📊 Confidence: {max(probabilities)*100:.2f}%")
    print(f"   Normal: {probabilities[0]*100:.2f}%")
    print(f"   Attack: {probabilities[1]*100:.2f}%")
    
    # Show key indicators
    print(f"\n📡 Key Indicators:")
    print(f"   Duration: {features['duration']} seconds")
    print(f"   Data Transfer: {features['src_bytes']} → {features['dst_bytes']} bytes")
    print(f"   Connection Count: {features['count']} connections")
    print(f"   Logged In: {'Yes' if features['logged_in'] else 'No'}")
    
    # Suspicious patterns
    if prediction == 1:
        print(f"\n⚠️  Suspicious Patterns:")
        if features['src_bytes'] == 0 and features['dst_bytes'] == 0:
            print("   - Zero byte transfer (possible scan)")
        if features['count'] > 5:
            print(f"   - High connection count ({features['count']})")
        if features['same_srv_rate'] < 0.3:
            print("   - Unusual service pattern")
    
    return prediction

def test_multiple_scenarios():
    """Test multiple IP scenarios"""
    
    model, scaler, encoders = load_model()
    if model is None:
        return
    
    print("\n" + "="*60)
    print("🧪 TESTING MULTIPLE SCENARIOS")
    print("="*60)
    
    scenarios = [
        {
            'name': 'Normal Web Browsing',
            'src': '192.168.1.100',
            'dst': '93.184.216.34',  # example.com
            'protocol': 'tcp',
            'service': 'http'
        },
        {
            'name': 'Internal Network Communication',
            'src': '192.168.1.50',
            'dst': '192.168.1.120',
            'protocol': 'tcp',
            'service': 'ftp'
        },
        {
            'name': 'Suspicious Port Scan',
            'src': '10.0.0.50',
            'dst': '192.168.1.1',
            'protocol': 'tcp',
            'service': 'private'
        },
        {
            'name': 'Failed Login Attempts',
            'src': '192.168.1.200',
            'dst': '10.0.0.10',
            'protocol': 'tcp',
            'service': 'smtp'
        },
        {
            'name': 'Potential DDoS Pattern',
            'src': '8.8.8.8',
            'dst': '192.168.1.100',
            'protocol': 'tcp',
            'service': 'http'
        }
    ]
    
    results = []
    for i, scenario in enumerate(scenarios, 1):
        print(f"\n📋 Scenario {i}: {scenario['name']}")
        print("-"*40)
        
        # Generate random features for more realistic simulation
        features = ip_to_features(scenario['src'], scenario['dst'], 
                                 scenario['protocol'], scenario['service'])
        
        # Modify features based on scenario
        if 'Port Scan' in scenario['name']:
            features['flag'] = 'S0'
            features['src_bytes'] = 0
            features['dst_bytes'] = 0
        elif 'Failed Login' in scenario['name']:
            features['num_failed_logins'] = random.randint(3, 10)
            features['logged_in'] = 0
        elif 'DDoS' in scenario['name']:
            features['count'] = random.randint(50, 200)
            features['same_srv_rate'] = 0.1
        
        # Convert to DataFrame
        df = pd.DataFrame([features])
        
        # Encode categorical features
        categorical_cols = ['protocol_type', 'service', 'flag']
        for col in categorical_cols:
            if col in df.columns:
                try:
                    df[col] = encoders[col].transform(df[col])
                except:
                    df[col] = 0
        
        # Scale and predict
        df_scaled = scaler.transform(df)
        prediction = model.predict(df_scaled)[0]
        prob = model.predict_proba(df_scaled)[0]
        
        # Display result
        result = "🔴 ATTACK" if prediction == 1 else "🟢 NORMAL"
        print(f"Source: {scenario['src']} → Destination: {scenario['dst']}")
        print(f"Result: {result} (Confidence: {max(prob)*100:.1f}%)")
        print(f"Details: Normal={prob[0]*100:.1f}%, Attack={prob[1]*100:.1f}%")
        
        results.append({
            'scenario': scenario['name'],
            'src': scenario['src'],
            'dst': scenario['dst'],
            'result': result,
            'confidence': max(prob)*100
        })
    
    # Summary
    print("\n" + "="*60)
    print("📊 SUMMARY")
    print("="*60)
    for r in results:
        print(f"{r['result']} - {r['scenario']}: {r['src']} → {r['dst']}")
    
    attacks = sum(1 for r in results if '🔴' in r['result'])
    print(f"\nDetected {attacks} out of {len(results)} suspicious connections")

def interactive_ip_check():
    """Interactive mode - user enters IPs"""
    
    model, scaler, encoders = load_model()
    if model is None:
        return
    
    while True:
        print("\n" + "="*60)
        print("🔍 INTERACTIVE IP ANALYSIS")
        print("="*60)
        
        # Get IPs from user
        src_ip = input("\nEnter Source IP: ").strip()
        dst_ip = input("Enter Destination IP: ").strip()
        
        if not src_ip or not dst_ip:
            print("❌ Please enter both IP addresses")
            continue
        
        protocol = input("Protocol (tcp/udp/icmp): ").strip().lower() or "tcp"
        service = input("Service (http/ftp/smtp/private): ").strip().lower() or "http"
        
        # Analyze
        prediction = analyze_traffic(src_ip, dst_ip, protocol, service)
        
        # Ask for another
        again = input("\n\nCheck another IP pair? (y/n): ").strip().lower()
        if again != 'y':
            print("\n👋 Exiting...")
            break

def main():
    """Main menu"""
    
    print("\n" + "="*60)
    print("🌐 NIDS - IP-BASED TRAFFIC ANALYZER")
    print("="*60)
    print("\nOptions:")
    print("1. Analyze single IP pair (interactive)")
    print("2. Test multiple scenarios (auto)")
    print("3. Quick test with sample IPs")
    
    choice = input("\nSelect option (1/2/3): ").strip()
    
    if choice == '1':
        interactive_ip_check()
    elif choice == '2':
        test_multiple_scenarios()
    else:
        # Quick test
        print("\n🧪 Quick Test:")
        analyze_traffic("192.168.1.100", "93.184.216.34", "tcp", "http")
        print("\n" + "-"*60)
        analyze_traffic("10.0.0.50", "192.168.1.1", "tcp", "private")

if __name__ == "__main__":
    main()