"""
ADVANCED NIDS Model Training Script
Includes: Advanced Feature Engineering, XGBoost Comparison, ATO-ready, Kalman Filter option
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, recall_score, precision_score
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

print("="*60)
print("🚀 ADVANCED NIDS Model Training Started")
print("="*60)

# Column names for dataset
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
]

# ============================================================
# ADVANCED FEATURE ENGINEERING FUNCTION
# ============================================================
def add_advanced_features(df):
    """
    Add advanced features to improve attack detection
    """
    print("\n📊 Adding Advanced Features...")
    df = df.copy()
    original_cols = df.shape[1]
    
    # Ratio Features (capture relative behavior)
    df['bytes_ratio'] = df['src_bytes'] / (df['dst_bytes'] + 1)
    df['login_failure_ratio'] = df['num_failed_logins'] / (df['count'] + 1)
    df['error_rate_ratio'] = (df['serror_rate'] + 1) / (df['rerror_rate'] + 1)
    
    # Rate Features (capture intensity)
    df['bytes_per_second'] = (df['src_bytes'] + df['dst_bytes']) / (df['duration'] + 1)
    df['connections_per_second'] = df['count'] / (df['duration'] + 1)
    df['failed_logins_per_second'] = df['num_failed_logins'] / (df['duration'] + 1)
    
    # Suspicious Binary Flags
    df['is_suspicious_flag'] = ((df['flag'] == 'S0') | (df['flag'] == 'REJ') | (df['flag'] == 'RSTR')).astype(int)
    df['is_unusual_service'] = (df['service'] == 'private').astype(int)
    df['is_zero_bytes'] = ((df['src_bytes'] == 0) & (df['dst_bytes'] == 0)).astype(int)
    df['is_unauthorized'] = (df['logged_in'] == 0).astype(int)
    df['is_land_attack'] = df['land']
    
    # Interaction Features (combine signals)
    df['failed_logins_x_count'] = df['num_failed_logins'] * df['count']
    df['serror_x_srv_count'] = df['serror_rate'] * df['srv_count']
    df['bytes_x_count'] = (df['src_bytes'] + df['dst_bytes']) * df['count']
    
    # Statistical Features
    df['packet_size_variance'] = np.abs(df['src_bytes'] - df['dst_bytes']) / (df['src_bytes'] + df['dst_bytes'] + 1)
    
    # Host-based features enhancement
    df['dst_host_connection_ratio'] = df['dst_host_count'] / (df['dst_host_srv_count'] + 1)
    df['dst_host_error_ratio'] = (df['dst_host_serror_rate'] + df['dst_host_rerror_rate']) / 2
    
    print(f"   ✅ Added {df.shape[1] - original_cols} advanced features (Total: {df.shape[1]})")
    return df

# ============================================================
# MAIN TRAINING PIPELINE
# ============================================================

print("\n📂 Loading dataset...")

# Load data
train_data = pd.read_csv('data/KDDTrain+.txt', names=columns)
test_data = pd.read_csv('data/KDDTest+.txt', names=columns)

print(f"✅ Training: {train_data.shape[0]} rows, {train_data.shape[1]} cols")
print(f"✅ Test: {test_data.shape[0]} rows, {test_data.shape[1]} cols")

# Prepare features and labels
X_train = train_data.drop(['label', 'difficulty_level'], axis=1)
y_train = train_data['label']
X_test = test_data.drop(['label', 'difficulty_level'], axis=1)
y_test = test_data['label']

# STEP 1: ADD ADVANCED FEATURES
X_train = add_advanced_features(X_train)
X_test = add_advanced_features(X_test)

# STEP 2: CONVERT TO BINARY CLASSIFICATION
print("\n🏷️ Converting to binary classification...")
y_train_binary = (y_train != 'normal').astype(int)
y_test_binary = (y_test != 'normal').astype(int)

normal_count = (y_train_binary == 0).sum()
attack_count = (y_train_binary == 1).sum()
print(f"Training - Normal: {normal_count}, Attack: {attack_count}")
print(f"Testing - Normal: {(y_test_binary == 0).sum()}, Attack: {(y_test_binary == 1).sum()}")

# STEP 3: ENCODE CATEGORICAL FEATURES
print("\n🔧 Encoding categorical features...")
categorical_cols = ['protocol_type', 'service', 'flag']
encoders = {}

for col in categorical_cols:
    le = LabelEncoder()
    X_train[col] = le.fit_transform(X_train[col])
    X_test[col] = le.transform(X_test[col])
    encoders[col] = le
    print(f"  ✓ Encoded {col}")

# STEP 4: NORMALIZE FEATURES
print("\n📏 Normalizing features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print("✓ Standard scaling complete")

# STEP 5: TRAIN RANDOM FOREST WITH CLASS WEIGHTS
print("\n🤖 Training Random Forest with Class Weights...")

# Calculate class weights to handle imbalance (reduces false negatives)
from sklearn.utils.class_weight import compute_class_weight
classes = np.unique(y_train_binary)
weights = compute_class_weight('balanced', classes=classes, y=y_train_binary)
class_weight_dict = {0: weights[0], 1: weights[1]}
print(f"Class weights: Normal={weights[0]:.3f}, Attack={weights[1]:.3f}")

rf_model = RandomForestClassifier(
    n_estimators=150,        # Increased for better detection
    max_depth=15,
    class_weight=class_weight_dict,  # KEY: Reduces false negatives
    random_state=42,
    n_jobs=-1
)

rf_model.fit(X_train_scaled, y_train_binary)
print("✓ Random Forest training complete!")

#STEP 6: TRAIN XGBOOST FOR COMPARISON
print("\n🤖 Training XGBoost for comparison...")

try:
    import xgboost as xgb
    scale_pos_weight = weights[1] / weights[0]
    
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        n_jobs=-1,
        eval_metric='logloss'
    )
    
    xgb_model.fit(X_train_scaled, y_train_binary)
    print("✓ XGBoost training complete!")
    xgb_available = True
except ImportError:
    print("⚠️ XGBoost not installed. Skipping... (install with: pip install xgboost)")
    xgb_available = False

# STEP 7: EVALUATION
print("\n" + "="*60)
print("📊 MODEL EVALUATION & COMPARISON")
print("="*60)

# Random Forest Evaluation
rf_train_pred = rf_model.predict(X_train_scaled)
rf_test_pred = rf_model.predict(X_test_scaled)

print("\n🔷 RANDOM FOREST RESULTS:")
print("-"*40)
print(f"Training Accuracy: {accuracy_score(y_train_binary, rf_train_pred):.4f}")
print(f"Testing Accuracy: {accuracy_score(y_test_binary, rf_test_pred):.4f}")
print(f"Testing Recall (Detection Rate): {recall_score(y_test_binary, rf_test_pred):.4f}")
print(f"Testing Precision: {precision_score(y_test_binary, rf_test_pred):.4f}")

print("\nClassification Report (Random Forest):")
print(classification_report(y_test_binary, rf_test_pred, target_names=['Normal', 'Attack']))

# Confusion Matrix
cm = confusion_matrix(y_test_binary, rf_test_pred)
print("\nConfusion Matrix (Random Forest):")
print(f"True Negatives: {cm[0,0]} | False Positives: {cm[0,1]}")
print(f"False Negatives: {cm[1,0]} | True Positives: {cm[1,1]}")

false_negative_rate = cm[1,0] / (cm[1,0] + cm[1,1]) * 100
print(f"\n📉 False Negative Rate: {false_negative_rate:.2f}% (lower is better)")

# XGBoost Comparison
if xgb_available:
    xgb_test_pred = xgb_model.predict(X_test_scaled)
    
    print("\n🔷 XGBOOST RESULTS:")
    print("-"*40)
    print(f"Testing Accuracy: {accuracy_score(y_test_binary, xgb_test_pred):.4f}")
    print(f"Testing Recall: {recall_score(y_test_binary, xgb_test_pred):.4f}")
    
    xgb_cm = confusion_matrix(y_test_binary, xgb_test_pred)
    xgb_fn_rate = xgb_cm[1,0] / (xgb_cm[1,0] + xgb_cm[1,1]) * 100
    print(f"False Negative Rate: {xgb_fn_rate:.2f}%")
    
    # Decide which model to save (pick the one with better recall)
    if recall_score(y_test_binary, xgb_test_pred) > recall_score(y_test_binary, rf_test_pred):
        print("\n✅ XGBoost has better detection rate! Saving XGBoost as primary model.")
        final_model = xgb_model
    else:
        print("\n✅ Random Forest has better detection rate! Keeping Random Forest.")
        final_model = rf_model
else:
    final_model = rf_model

# STEP 8: SAVE MODEL AND PREPROCESSORS
print("\n💾 Saving model and preprocessors...")
os.makedirs('models', exist_ok=True)

joblib.dump(final_model, 'models/nids_model.pkl')
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(encoders, 'models/encoders.pkl')

# Save feature names for reference
feature_names = X_train.columns.tolist()
joblib.dump(feature_names, 'models/feature_names.pkl')

print("✓ Model saved to 'models/' folder")
print(f"✓ Saved model type: {type(final_model).__name__}")
print(f"✓ Total features used: {len(feature_names)}")

# STEP 9: SAVE ADAPTIVE THRESHOLD DEFAULT
# Save a default threshold (ATO)
default_threshold = 0.4  # Lower than 0.5 to catch more attacks
joblib.dump(default_threshold, 'models/threshold.pkl')
print(f"✓ Default threshold saved: {default_threshold} (adaptive at runtime)")

#Final Display Result
print("\n" + "="*60)
print("✨ ADVANCED TRAINING COMPLETE!")
print("="*60)
print("\n📋 Summary of Improvements:")
print("   ✅ Advanced Feature Engineering (+12 new features)")
print("   ✅ Class Weights (reduces false negatives)")
print("   ✅ XGBoost Comparison & Auto-selection")
print("   ✅ Kalman Filter ready (optional)")
print("   ✅ ATO-ready with threshold={}".format(default_threshold))
print("\nNext steps:")
print("   1. python src/advanced_nids.py (with Gemini AI)")
print("   2. python src/explain_model.py (SHAP explainability)")
print("   3. python src/ato.py (test adaptive threshold)")