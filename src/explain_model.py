"""
SHAP Explainability - Advanced Features Version
"""

import pandas as pd
import numpy as np
import joblib
import warnings
warnings.filterwarnings('ignore')

def load_model():
    model = joblib.load('models/nids_model.pkl')
    scaler = joblib.load('models/scaler.pkl')
    encoders = joblib.load('models/encoders.pkl')
    selector = joblib.load('models/selector.pkl')
    feature_names = joblib.load('models/feature_names.pkl')
    return model, scaler, encoders, selector, feature_names

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

def main():
    print("="*60)
    print("Model Explainability - Feature Importance")
    print("="*60)
    
    model, scaler, encoders, selector, feature_names = load_model()
    
    # Test cases
    test_cases = [
        ("NORMAL - HTTP", {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF',
            'src_bytes': 181, 'dst_bytes': 5450, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 1,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 5, 'srv_count': 5, 'serror_rate': 0, 'srv_serror_rate': 0,
            'rerror_rate': 0, 'srv_rerror_rate': 0, 'same_srv_rate': 0.9,
            'diff_srv_rate': 0.1, 'srv_diff_host_rate': 0, 'dst_host_count': 10,
            'dst_host_srv_count': 10, 'dst_host_same_srv_rate': 0.5,
            'dst_host_diff_srv_rate': 0.5, 'dst_host_same_src_port_rate': 0,
            'dst_host_srv_diff_host_rate': 0, 'dst_host_serror_rate': 0,
            'dst_host_srv_serror_rate': 0, 'dst_host_rerror_rate': 0,
            'dst_host_srv_rerror_rate': 0
        }),
        ("ATTACK - Port Scan", {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'S0',
            'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 10, 'srv_count': 10, 'serror_rate': 0.5, 'srv_serror_rate': 0.5,
            'rerror_rate': 0, 'srv_rerror_rate': 0, 'same_srv_rate': 0.1,
            'diff_srv_rate': 0.9, 'srv_diff_host_rate': 0, 'dst_host_count': 10,
            'dst_host_srv_count': 10, 'dst_host_same_srv_rate': 0.5,
            'dst_host_diff_srv_rate': 0.5, 'dst_host_same_src_port_rate': 0,
            'dst_host_srv_diff_host_rate': 0, 'dst_host_serror_rate': 0,
            'dst_host_srv_serror_rate': 0, 'dst_host_rerror_rate': 0,
            'dst_host_srv_rerror_rate': 0
        })
    ]
    
    for name, conn in test_cases:
        df = pd.DataFrame([conn])
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
        
        print(f"\n{name}")
        print("-"*40)
        print(f"Prediction: {'ATTACK' if pred == 1 else 'NORMAL'}")
        print(f"Confidence: {prob[1]*100 if pred==1 else prob[0]*100:.1f}%")

if __name__ == "__main__":
    main()