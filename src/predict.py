"""
Interactive NIDS Model Testing
Input your own network connection details and get real-time predictions
"""

import pandas as pd
import numpy as np
import joblib
import os

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Print nice header"""
    print("="*60)
    print("🔍 NIDS - Network Intrusion Detection System")
    print("="*60)
    print()

def get_user_input():
    """Get network connection details from user"""
    
    print("📊 Enter Network Connection Details")
    print("-"*40)
    print("(Press Enter to use default values)")
    print()
    
    print("📡 Basic Connection Info:")
    protocol = input("  Protocol (tcp/udp/icmp) [tcp]: ").strip().lower() or "tcp"
    service = input("  Service (http/ftp/smtp/private/others) [http]: ").strip().lower() or "http"
    flag = input("  Flag (SF/S0/REJ/RSTR) [SF]: ").strip().upper() or "SF"
    
    print("\n📦 Packet Sizes:")
    src_bytes = input("  Source bytes [0]: ").strip() or "0"
    dst_bytes = input("  Destination bytes [0]: ").strip() or "0"
    
    print("\n🚩 Connection Flags:")
    land = input("  Land attack? (0/1) [0]: ").strip() or "0"
    wrong_fragment = input("  Wrong fragments? (0/1) [0]: ").strip() or "0"
    urgent = input("  Urgent packets? (0/1) [0]: ").strip() or "0"
    
    # Login info
    print("\n🔐 Login Information:")
    logged_in = input("  Logged in? (0/1) [0]: ").strip() or "0"
    num_failed_logins = input("  Failed login attempts [0]: ").strip() or "0"
    root_shell = input("  Root shell accessed? (0/1) [0]: ").strip() or "0"
    su_attempted = input("  SU attempted? (0/1) [0]: ").strip() or "0"
    
    # Connection counts
    print("\n📈 Connection Statistics:")
    count = input("  Connections to same host in 2 secs [1]: ").strip() or "1"
    srv_count = input("  Connections to same service [1]: ").strip() or "1"
    
    # Rates
    serror_rate = input("  SYN error rate [0]: ").strip() or "0"
    srv_serror_rate = input("  Service SYN error rate [0]: ").strip() or "0"
    rerror_rate = input("  REJ error rate [0]: ").strip() or "0"
    srv_rerror_rate = input("  Service REJ error rate [0]: ").strip() or "0"
    
    # Host statistics
    print("\n🏠 Host Statistics:")
    same_srv_rate = input("  Same service rate [1]: ").strip() or "1"
    diff_srv_rate = input("  Different service rate [0]: ").strip() or "0"
    
    # Destination host
    dst_host_count = input("  Destination host count [1]: ").strip() or "1"
    dst_host_srv_count = input("  Destination host service count [1]: ").strip() or "1"
    dst_host_same_srv_rate = input("  Dest host same service rate [1]: ").strip() or "1"
    
    # Create dictionary with all features (rest default to 0)
    connection = {
        'duration': 0, 'protocol_type': protocol, 'service': service, 'flag': flag,
        'src_bytes': int(src_bytes), 'dst_bytes': int(dst_bytes), 'land': int(land),
        'wrong_fragment': int(wrong_fragment), 'urgent': int(urgent), 'hot': 0,
        'num_failed_logins': int(num_failed_logins), 'logged_in': int(logged_in),
        'num_compromised': 0, 'root_shell': int(root_shell), 'su_attempted': int(su_attempted),
        'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
        'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': int(count), 'srv_count': int(srv_count), 'serror_rate': float(serror_rate),
        'srv_serror_rate': float(srv_serror_rate), 'rerror_rate': float(rerror_rate),
        'srv_rerror_rate': float(srv_rerror_rate), 'same_srv_rate': float(same_srv_rate),
        'diff_srv_rate': float(diff_srv_rate), 'srv_diff_host_rate': 0,
        'dst_host_count': int(dst_host_count), 'dst_host_srv_count': int(dst_host_srv_count),
        'dst_host_same_srv_rate': float(dst_host_same_srv_rate), 'dst_host_diff_srv_rate': 0,
        'dst_host_same_src_port_rate': 0, 'dst_host_srv_diff_host_rate': 0,
        'dst_host_serror_rate': 0, 'dst_host_srv_serror_rate': 0,
        'dst_host_rerror_rate': 0, 'dst_host_srv_rerror_rate': 0
    }
    
    return connection

def predict_connection(connection, model, scaler, encoders):
    """Predict if connection is normal or attack"""
    
    # Convert to DataFrame
    df = pd.DataFrame([connection])
    
    # Encode categorical features
    categorical_cols = ['protocol_type', 'service', 'flag']
    for col in categorical_cols:
        if col in df.columns:
            try:
                df[col] = encoders[col].transform(df[col])
            except ValueError:
                print(f"⚠️  Warning: Unknown {col} value. Using default.")
                # Use the first available encoded value
                df[col] = encoders[col].transform([encoders[col].classes_[0]])
    
    # Scale features
    df_scaled = scaler.transform(df)
    
    # Predict
    prediction = model.predict(df_scaled)[0]
    probabilities = model.predict_proba(df_scaled)[0]
    
    return prediction, probabilities

def display_result(prediction, probabilities, connection):
    """Display prediction results nicely"""
    
    print("\n" + "="*60)
    print("📊 PREDICTION RESULT")
    print("="*60)
    
    # Result
    if prediction == 1:
        print("\n🔴 STATUS: ATTACK DETECTED!")
        print("⚠️  This connection appears to be malicious!")
    else:
        print("\n🟢 STATUS: NORMAL TRAFFIC")
        print("✅ This connection appears to be safe!")
    
    # Confidence
    confidence = max(probabilities) * 100
    print(f"\n📈 Confidence: {confidence:.2f}%")
    
    # Detailed probabilities
    print(f"\n📊 Detailed Analysis:")
    print(f"   Normal probability: {probabilities[0]*100:.2f}%")
    print(f"   Attack probability: {probabilities[1]*100:.2f}%")
    
    # Connection summary
    print(f"\n📡 Connection Summary:")
    print(f"   Protocol: {connection['protocol_type']}")
    print(f"   Service: {connection['service']}")
    print(f"   Flag: {connection['flag']}")
    print(f"   Source Bytes: {connection['src_bytes']}")
    print(f"   Destination Bytes: {connection['dst_bytes']}")
    print(f"   Logged In: {'Yes' if connection['logged_in'] else 'No'}")
    
    # Risk factors if attack detected)
    if prediction == 1:
        print(f"\n⚠️  Suspicious Indicators:")
        if connection['flag'] in ['S0', 'REJ', 'RSTR']:
            print("   - Unusual connection flag")
        if connection['num_failed_logins'] > 0:
            print("   - Failed login attempts detected")
        if connection['src_bytes'] == 0 and connection['dst_bytes'] == 0:
            print("   - Zero byte transfer (possible scan)")
        if connection['service'] == 'private':
            print("   - Connection to private/uncommon service")
        if connection['same_srv_rate'] < 0.5:
            print("   - Unusual service pattern")
    
    print("\n" + "="*60)

def main():
    """Main interactive loop"""
    
    clear_screen()
    print_header()
    
    # Load model
    print("📂 Loading model and preprocessing tools...")
    try:
        model = joblib.load('models/nids_model.pkl')
        scaler = joblib.load('models/scaler.pkl')
        encoders = joblib.load('models/encoders.pkl')
        print("✅ Model loaded successfully!\n")
    except FileNotFoundError:
        print("❌ Model not found!")
        print("\nPlease train the model first:")
        print("  python src/train_model.py")
        return
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return
    
    while True:
        print_header()
        
        # Get user input
        connection = get_user_input()
        
        # Make prediction
        prediction, probabilities = predict_connection(connection, model, scaler, encoders)
        
        # Display result
        display_result(prediction, probabilities, connection)
        
        # Ask for another prediction
        print("\n🔄 Options:")
        print("  Enter 'y' - Test another connection")
        print("  Enter 'n' - Exit")
        
        choice = input("\nTest another connection? (y/n): ").strip().lower()
        
        if choice != 'y':
            print("\n👋 Thank you for using NIDS!")
            print("="*60)
            break
        
        clear_screen()

if __name__ == "__main__":
    main()