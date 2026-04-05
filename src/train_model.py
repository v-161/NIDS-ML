"""
NIDS Training - Hybrid Architecture
"""

import pandas as pd
import numpy as np
import os
from sklearn.ensemble import RandomForestClassifier, IsolationForest, StackingClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, recall_score, precision_score, f1_score
from sklearn.linear_model import LogisticRegression
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from imblearn.over_sampling import SMOTE
import joblib
import warnings
warnings.filterwarnings('ignore')

print("="*70)
print("NIDS TRAINING - HYBRID ARCHITECTURE")
print("="*70)

# Column names
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

# Load data
train_data = pd.read_csv('data/KDDTrain+.txt', names=columns)
test_data = pd.read_csv('data/KDDTest+.txt', names=columns)

full_data = pd.concat([train_data, test_data], ignore_index=True)

X = full_data.drop(['label', 'difficulty_level'], axis=1)
y = (full_data['label'] != 'normal').astype(int)

print(f"Samples: {len(X):,} | Normal: {(y==0).sum():,} | Attack: {(y==1).sum():,}")

# Feature engineering
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

X = add_advanced_features(X)

# Encode categorical
categorical_cols = ['protocol_type', 'service', 'flag']
encoders = {}
for col in categorical_cols:
    le = LabelEncoder()
    X[col] = le.fit_transform(X[col].astype(str))
    encoders[col] = le

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# Scale
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# SMOTE
smote = SMOTE(random_state=42)
X_train_balanced, y_train_balanced = smote.fit_resample(X_train_scaled, y_train)

# Feature selection
selector = SelectKBest(mutual_info_classif, k=35)
X_train_selected = selector.fit_transform(X_train_balanced, y_train_balanced)
X_test_selected = selector.transform(X_test_scaled)

# Isolation Forest on normal traffic only
X_train_normal = X_train_selected[y_train_balanced == 0]
iso_forest = IsolationForest(contamination=0.08, random_state=42, n_estimators=300)
iso_forest.fit(X_train_normal)

# Random Forest
rf_model = RandomForestClassifier(
    n_estimators=700,
    max_depth=None,
    min_samples_split=2,
    class_weight={0: 0.8, 1: 4.0},
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_train_selected, y_train_balanced)

# XGBoost
xgb_available = False
try:
    import xgboost as xgb
    xgb_model = xgb.XGBClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.03,
        scale_pos_weight=4,
        random_state=42,
        n_jobs=-1
    )
    xgb_model.fit(X_train_selected, y_train_balanced)
    xgb_available = True
except:
    pass

# LightGBM
lgb_available = False
try:
    import lightgbm as lgb
    lgb_model = lgb.LGBMClassifier(
        n_estimators=500,
        max_depth=-1,
        learning_rate=0.03,
        scale_pos_weight=4,
        random_state=42,
        n_jobs=-1,
        verbose=-1
    )
    lgb_model.fit(X_train_selected, y_train_balanced)
    lgb_available = True
except:
    pass

# Stacking
estimators = [('rf', rf_model)]
if xgb_available:
    estimators.append(('xgb', xgb_model))
if lgb_available:
    estimators.append(('lgb', lgb_model))

stack_model = StackingClassifier(
    estimators=estimators,
    final_estimator=LogisticRegression(C=0.5),
    cv=3,
    stack_method='predict_proba'
)
stack_model.fit(X_train_selected, y_train_balanced)

# Predictions
stack_probs = stack_model.predict_proba(X_test_selected)[:, 1]
iso_pred = iso_forest.predict(X_test_selected)
iso_anomaly = (iso_pred == -1).astype(int)

combined_probs = np.where(iso_anomaly == 1, np.maximum(stack_probs, 0.55), stack_probs)

# Find optimal threshold (balance recall and precision)
thresholds = [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60]
best_f1 = 0
best_threshold = 0.50

for thresh in thresholds:
    preds = (combined_probs >= thresh).astype(int)
    recall = recall_score(y_test, preds)
    precision = precision_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    if f1 > best_f1:
        best_f1 = f1
        best_threshold = thresh

final_preds = (combined_probs >= best_threshold).astype(int)

# Results
cm = confusion_matrix(y_test, final_preds)
accuracy = accuracy_score(y_test, final_preds)
recall = recall_score(y_test, final_preds)
precision = precision_score(y_test, final_preds)
f1 = f1_score(y_test, final_preds)

fn_rate = cm[1,0] / (cm[1,0] + cm[1,1]) * 100
fp_rate = cm[0,1] / (cm[0,0] + cm[0,1]) * 100

print("\n" + "="*70)
print("FINAL RESULTS")
print("="*70)
print(f"Accuracy: {accuracy*100:.2f}%")
print(f"Detection Rate: {recall*100:.2f}%")
print(f"Precision: {precision*100:.2f}%")
print(f"F1-Score: {f1*100:.2f}%")
print(f"False Negative Rate: {fn_rate:.2f}%")
print(f"False Positive Rate: {fp_rate:.2f}%")

print("\nConfusion Matrix:")
print(f"True Negatives: {cm[0,0]:,} | False Positives: {cm[0,1]:,}")
print(f"False Negatives: {cm[1,0]:,} | True Positives: {cm[1,1]:,}")

# Save
os.makedirs('models', exist_ok=True)
joblib.dump(stack_model, 'models/nids_model.pkl')
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(encoders, 'models/encoders.pkl')
joblib.dump(selector, 'models/selector.pkl')
joblib.dump(iso_forest, 'models/iso_forest.pkl')
joblib.dump(best_threshold, 'models/threshold.pkl')
joblib.dump(X.columns.tolist(), 'models/feature_names.pkl')

print("\nModels saved to 'models/' folder")
print(f"Threshold: {best_threshold:.2f}")