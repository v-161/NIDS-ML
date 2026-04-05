"""
NIDS Predictor - Advanced Features Version
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
    """Add same features used during training"""
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

def get_user_input():
    print("\n" + "="*60)
    print("NIDS - Network Intrusion Detection")
    print("="*60)
    
    print("\nEnter Connection Details:")
    protocol = input("Protocol (tcp/udp/icmp) [tcp]: ").strip().lower() or "tcp"
    service = input("Service (http/ftp/smtp/private) [http]: ").strip().lower() or "http"
    flag = input("Flag (SF/S0/REJ) [SF]: ").strip().upper() or "SF"
    src_bytes = int(input("Source bytes [0]: ").strip() or "0")
    dst_bytes = int(input("Destination bytes [0]: ").strip() or "0")
    logged_in = int(input("Logged in (0/1) [1]: ").strip() or "1")
    failed_logins = int(input("Failed logins [0]: ").strip() or "0")
    count = int(input("Connections [5]: ").strip() or "5")
    same_srv_rate = float(input("Same service rate [0.9]: ").strip() or "0.9")
    diff_srv_rate = float(input("Different service rate [0.1]: ").strip() or "0.1")
    
    return {
        'duration': 0, 'protocol_type': protocol, 'service': service, 'flag': flag,
        'src_bytes': src_bytes, 'dst_bytes': dst_bytes, 'land': 0, 'wrong_fragment': 0,
        'urgent': 0, 'hot': 0, 'num_failed_logins': failed_logins, 'logged_in': logged_in,
        'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
        'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0,
        'is_host_login': 0, 'is_guest_login': 0, 'count': count, 'srv_count': count,
        'serror_rate': 0.5 if flag == 'S0' else 0, 'srv_serror_rate': 0.5 if flag == 'S0' else 0,
        'rerror_rate': 0, 'srv_rerror_rate': 0, 'same_srv_rate': same_srv_rate,
        'diff_srv_rate': diff_srv_rate, 'srv_diff_host_rate': 0, 'dst_host_count': 10,
        'dst_host_srv_count': 10, 'dst_host_same_srv_rate': 0.5, 'dst_host_diff_srv_rate': 0.5,
        'dst_host_same_src_port_rate': 0, 'dst_host_srv_diff_host_rate': 0,
        'dst_host_serror_rate': 0, 'dst_host_srv_serror_rate': 0, 'dst_host_rerror_rate': 0,
        'dst_host_srv_rerror_rate': 0
    }

def main():
    model, scaler, encoders, selector, feature_names = load_model()
    if model is None:
        return
    
    conn = get_user_input()
    df = pd.DataFrame([conn])
    df = add_advanced_features(df)
    
    for col in ['protocol_type', 'service', 'flag']:
        df[col] = encoders[col].transform(df[col])
    
    # Ensure all expected columns exist
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
        print("RESULT: ATTACK DETECTED")
        print(f"Confidence: {prob[1]*100:.1f}%")
    else:
        print("RESULT: NORMAL TRAFFIC")
        print(f"Confidence: {prob[0]*100:.1f}%")
    print("="*60)

if __name__ == "__main__":
    main()