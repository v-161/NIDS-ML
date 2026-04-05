"""
SHAP Explainability - Understand why model makes decisions
"""

import shap
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt

def explain_prediction(features, feature_names):
    """Explain a single prediction using SHAP"""
    
    # Load model
    model = joblib.load('models/nids_model.pkl')
    
    # Create SHAP explainer
    explainer = shap.TreeExplainer(model)
    
    # Calculate SHAP values
    shap_values = explainer.shap_values(features)
    
    # For binary classification, take the positive class (attack)
    if isinstance(shap_values, list):
        shap_values = shap_values[1]
    
    # Create summary plot
    print("\n📊 Top 5 Features Contributing to Decision:")
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'shap_value': np.abs(shap_values[0])
    }).sort_values('shap_value', ascending=False).head(5)
    
    for i, row in feature_importance.iterrows():
        print(f"   • {row['feature']}: {row['shap_value']:.4f}")
    
    # Force plot for single prediction
    shap.force_plot(explainer.expected_value[1] if isinstance(explainer.expected_value, list) else explainer.expected_value, 
                    shap_values[0], 
                    features[0],
                    feature_names=feature_names,
                    matplotlib=True,
                    show=False)
    plt.savefig('shap_force_plot.png', bbox_inches='tight')
    print("\n✅ SHAP plot saved as 'shap_force_plot.png'")
    
    return shap_values

# Quick test
if __name__ == "__main__":
    print("Testing SHAP Explainability...")
    # Load a sample
    model = joblib.load('models/nids_model.pkl')
    scaler = joblib.load('models/scaler.pkl')
    encoders = joblib.load('models/encoders.pkl')
    
    # Create a sample attack connection
    sample = pd.DataFrame([{
        'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'S0',
        'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0,
        'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
        'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
        'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
        'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 10, 'srv_count': 10, 'serror_rate': 0.5, 'srv_serror_rate': 0.5,
        'rerror_rate': 0, 'srv_rerror_rate': 0, 'same_srv_rate': 0.1,
        'diff_srv_rate': 0.9, 'srv_diff_host_rate': 0.5, 'dst_host_count': 10,
        'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.1,
        'dst_host_diff_srv_rate': 0.9, 'dst_host_same_src_port_rate': 0.5,
        'dst_host_srv_diff_host_rate': 0.5, 'dst_host_serror_rate': 0.5,
        'dst_host_srv_serror_rate': 0.5, 'dst_host_rerror_rate': 0,
        'dst_host_srv_rerror_rate': 0
    }])
    
    # Encode
    for col in ['protocol_type', 'service', 'flag']:
        sample[col] = encoders[col].transform(sample[col])
    
    # Scale
    sample_scaled = scaler.transform(sample)
    
    # Explain
    explain_prediction(sample_scaled, sample.columns.tolist())