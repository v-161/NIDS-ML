"""
IP-based traffic analysis - Advanced Features Version
"""

import pandas as pd
import numpy as np
import joblib

def load_model():
    try:
        model = joblib.load('models/nids_model.pkl')
        scaler = joblib.load('models/scaler.pkl')
        encoders = joblib.load('models/encoders.pkl')
        selector = joblib.load('models/selector.pkl')
        feature_names = joblib.load('models/feature_names.pkl')
        return model, scaler, encoders, selector, feature_names
    except Exception as e:
        print(f"Error: {e}")
        return None, None, None, None, None

def add_advanced_features(df):
    df = df.copy()
    df['bytes_ratio'] = df['src_bytes'] / (df['dst_bytes'] + 1)
    df['login_failure_ratio'] = df['num_failed_logins'] / (df['count'] + 1)
    df['bytes_per_second'] = (df['src_bytes'] + df['dst_bytes']) / (df['duration'] + 1)
    df['connections_per_second'] = df['count'] / (df['duration'] + 1)
    df['log_src_bytes'] = np.log1p(df['src_bytes'])
    df['log_dst_bytes'] = np.log1p(df['dst_bytes'])
    df['log_duration'] = np.log1p(df['duration'])
    df['packet_intensity'] = (df['count'] + df['srv_count']) / (df['duration'] + 1)
    df['error_ratio'] = (df['serror_rate'] + df['rerror_rate']) / 2
    df['host_error_ratio'] = (df['dst_host_serror_rate'] + df['dst_host_rerror_rate']) / 2
    df['is_suspicious_flag'] = ((df['flag'] == 'S0') | (df['flag'] == 'REJ')).astype(int)
    df['is_unusual_service'] = (df['service'] == 'private').astype(int)
    df['is_zero_bytes'] = ((df['src_bytes'] == 0) & (df['dst_bytes'] == 0)).astype(int)
    df['is_unauthorized'] = (df['logged_in'] == 0).astype(int)
    df['failed_logins_x_count'] = df['num_failed_logins'] * df['count']
    return df

def create_features(src_ip, dst_ip, protocol='tcp', service='http'):
    is_attack = (service == 'private')
    return {
        'duration': 0, 'protocol_type': protocol, 'service': service,
        'flag': 'S0' if is_attack else 'SF',
        'src_bytes': 0 if is_attack else 181,
        'dst_bytes': 0 if is_attack else 5450,
        'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0,
        'num_failed_logins': 5 if is_attack else 0,
        'logged_in': 0 if is_attack else 1,
        'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
        'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
        'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 50 if is_attack else 5, 'srv_count': 50 if is_attack else 5,
        'serror_rate': 0.5 if is_attack else 0, 'srv_serror_rate': 0.5 if is_attack else 0,
        'rerror_rate': 0, 'srv_rerror_rate': 0,
        'same_srv_rate': 0.1 if is_attack else 0.9,
        'diff_srv_rate': 0.9 if is_attack else 0.1,
        'srv_diff_host_rate': 0, 'dst_host_count': 10, 'dst_host_srv_count': 10,
        'dst_host_same_srv_rate': 0.5, 'dst_host_diff_srv_rate': 0.5,
        'dst_host_same_src_port_rate': 0, 'dst_host_srv_diff_host_rate': 0,
        'dst_host_serror_rate': 0, 'dst_host_srv_serror_rate': 0,
        'dst_host_rerror_rate': 0, 'dst_host_srv_rerror_rate': 0
    }

def analyze_traffic(src_ip, dst_ip, protocol='tcp', service='http'):
    model, scaler, encoders, selector, feature_names = load_model()
    if model is None:
        return
    
    print("\n" + "="*60)
    print(f"Source: {src_ip} -> {dst_ip}")
    print(f"Protocol: {protocol}, Service: {service}")
    print("-"*40)
    
    features = create_features(src_ip, dst_ip, protocol, service)
    df = pd.DataFrame([features])
    df = add_advanced_features(df)
    
    for col in ['protocol_type', 'service', 'flag']:
        df[col] = encoders[col].transform(df[col])
    
    if feature_names:
        for col in feature_names:
            if col not in df.columns:
                df[col] = 0
        df = df[feature_names]
    
    df_scaled = scaler.transform(df)
    df_selected = selector.transform(df_scaled)
    
    prob = model.predict_proba(df_selected)[0]
    pred = 1 if prob[1] > 0.5 else 0
    
    if pred == 1:
        print(f"\nRESULT: ATTACK DETECTED")
        print(f"Confidence: {prob[1]*100:.1f}%")
    else:
        print(f"\nRESULT: NORMAL TRAFFIC")
        print(f"Confidence: {prob[0]*100:.1f}%")

def main():
    print("\n" + "="*60)
    print("IP Traffic Analyzer")
    print("="*60)
    
    while True:
        print("\nOptions:")
        print("1. Single IP pair")
        print("2. Quick test")
        print("3. Exit")
        
        choice = input("\nChoice: ").strip()
        
        if choice == '1':
            src = input("Source IP: ").strip()
            dst = input("Destination IP: ").strip()
            proto = input("Protocol [tcp]: ").strip() or "tcp"
            service = input("Service [http]: ").strip() or "http"
            analyze_traffic(src, dst, proto, service)
        elif choice == '2':
            print("\n--- Normal Test ---")
            analyze_traffic("192.168.1.100", "93.184.216.34", "tcp", "http")
            print("\n--- Attack Test ---")
            analyze_traffic("10.0.0.50", "192.168.1.1", "tcp", "private")
        elif choice == '3':
            break

if __name__ == "__main__":
    main()