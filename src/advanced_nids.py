"""
Advanced NIDS with Gemini AI - Uses trained model with feature selection
"""

import pandas as pd
import numpy as np
import joblib
from mitigation import get_mitigation_steps

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

def analyze_connection():
    model, scaler, encoders, selector, feature_names = load_model()
    if model is None:
        return
    
    print("\n" + "="*60)
    print("Advanced NIDS with Gemini AI")
    print("="*60)
    
    src_ip = input("Source IP: ").strip()
    dst_ip = input("Destination IP: ").strip()
    protocol = input("Protocol [tcp]: ").strip() or "tcp"
    service = input("Service [http]: ").strip().lower() or "http"
    flag = input("Flag [SF]: ").strip().upper() or "SF"
    logged_in = int(input("Logged in (0/1) [1]: ").strip() or "1")
    count = int(input("Connections [5]: ").strip() or "5")
    
    is_attack = (service == 'private' or flag == 'S0')
    
    features = {
        'duration': 0, 'protocol_type': protocol, 'service': service, 'flag': flag,
        'src_bytes': 0 if is_attack else 181, 'dst_bytes': 0 if is_attack else 5450,
        'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0,
        'num_failed_logins': 5 if is_attack else 0, 'logged_in': logged_in,
        'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
        'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
        'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': count, 'srv_count': count,
        'serror_rate': 0.5 if flag == 'S0' else 0, 'srv_serror_rate': 0.5 if flag == 'S0' else 0,
        'rerror_rate': 0, 'srv_rerror_rate': 0,
        'same_srv_rate': 0.1 if is_attack else 0.9, 'diff_srv_rate': 0.9 if is_attack else 0.1,
        'srv_diff_host_rate': 0, 'dst_host_count': 10, 'dst_host_srv_count': 10,
        'dst_host_same_srv_rate': 0.5, 'dst_host_diff_srv_rate': 0.5,
        'dst_host_same_src_port_rate': 0, 'dst_host_srv_diff_host_rate': 0,
        'dst_host_serror_rate': 0, 'dst_host_srv_serror_rate': 0,
        'dst_host_rerror_rate': 0, 'dst_host_srv_rerror_rate': 0
    }
    
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
    
    print("\n" + "="*60)
    if pred == 1:
        print("VERDICT: ATTACK DETECTED")
        print(f"Confidence: {prob[1]*100:.1f}%")
        
        indicators = []
        if service == 'private':
            indicators.append("Private/uncommon service")
        if flag == 'S0':
            indicators.append("S0 flag - no response")
        if logged_in == 0:
            indicators.append("Not logged in")
        if count > 10:
            indicators.append(f"High connection count ({count})")
        
        print("\nSuspicious Indicators:")
        for ind in indicators:
            print(f"  - {ind}")
        
        print("\n" + "="*60)
        print("GEMINI AI - MITIGATION RECOMMENDATIONS")
        print("="*60)
        
        mitigation = get_mitigation_steps(
            "Port Scan" if service == 'private' else "Suspicious Activity",
            {'src_ip': src_ip, 'dst_ip': dst_ip, 'protocol': protocol, 'service': service},
            prob[1]*100
        )
        print(mitigation)
    else:
        print("VERDICT: NORMAL TRAFFIC")
        print(f"Confidence: {prob[0]*100:.1f}%")
    print("="*60)

if __name__ == "__main__":
    analyze_connection()