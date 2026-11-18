import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import pickle
import warnings
warnings.filterwarnings('ignore')

class HeartDiseasePredictor:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.evaluation_results = {}
        
    def load_data(self, filepath):
        """Load the Framingham dataset"""
        df = pd.read_csv(filepath)
        print(f"✓ Dataset loaded: {df.shape[0]} records, {df.shape[1]} features")
        return df
    
    def preprocess_data(self, df):
        """Preprocess and clean the data"""
        print("\n--- Data Preprocessing ---")
        
        # Handle missing values
        print(f"Missing values before handling:\n{df.isnull().sum()}")
        
        # Fill missing values with median for numeric columns
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        for col in numeric_columns:
            if df[col].isnull().sum() > 0:
                df[col].fillna(df[col].median(), inplace=True)
        
        print(f"✓ Missing values handled")
        
        # Remove outliers using IQR method
        Q1 = df.quantile(0.25)
        Q3 = df.quantile(0.75)
        IQR = Q3 - Q1
        
        cols_to_check = ['age', 'sysBP', 'diaBP', 'BMI', 'heartRate', 'glucose', 'totChol']
        cols_to_check = [col for col in cols_to_check if col in df.columns]
        
        df = df[~((df[cols_to_check] < (Q1[cols_to_check] - 1.5 * IQR[cols_to_check])) | 
                   (df[cols_to_check] > (Q3[cols_to_check] + 1.5 * IQR[cols_to_check]))).any(axis=1)]
        
        print(f"✓ Outliers removed: {df.shape[0]} records remaining")
        
        return df
    
    def engineer_features(self, df):
        """Create additional features for better prediction"""
        print("\n--- Feature Engineering ---")
        
        if 'weight_kg' in df.columns and 'height_cm' in df.columns:
            df['BMI'] = df['weight_kg'] / ((df['height_cm'] / 100) ** 2)
            print("✓ BMI calculated")
        
        if 'sysBP' in df.columns and 'diaBP' in df.columns:
            df['pulsePressure'] = df['sysBP'] - df['diaBP']
            print("✓ Pulse pressure calculated")
        
        if 'age' in df.columns:
            df['ageGroup'] = pd.cut(df['age'], bins=[0, 40, 50, 60, 100], 
                                    labels=[1, 2, 3, 4]).astype(int)
            print("✓ Age groups created")
        
        risk_cols = ['currentSmoker', 'diabetes', 'prevalentStroke', 'prevalentHyp']
        available_risk_cols = [col for col in risk_cols if col in df.columns]
        if available_risk_cols:
            df['riskFactorCount'] = df[available_risk_cols].sum(axis=1)
            print("✓ Risk factor count calculated")
        
        return df
    
    def prepare_features(self, df, target_column='TenYearCHD'):
        """Prepare features and target"""
        print("\n--- Feature Preparation ---")
        
        feature_cols = ['male', 'age', 'education', 'currentSmoker', 'cigsPerDay', 
                       'BPMeds', 'prevalentStroke', 'prevalentHyp', 'diabetes', 
                       'totChol', 'sysBP', 'diaBP', 'BMI', 'heartRate', 'glucose']
        
        available_features = [col for col in feature_cols if col in df.columns]
        
        if 'pulsePressure' in df.columns:
            available_features.append('pulsePressure')
        if 'ageGroup' in df.columns:
            available_features.append('ageGroup')
        if 'riskFactorCount' in df.columns:
            available_features.append('riskFactorCount')
        
        self.feature_names = available_features
        
        X = df[available_features].copy()
        y = df[target_column].copy()
        
        print(f"✓ Features selected: {len(available_features)}")
        print(f"  Features: {', '.join(available_features)}")
        print(f"✓ Target classes: {np.unique(y)}")
        print(f"  Class distribution: {np.bincount(y.astype(int))}")
        
        return X, y, available_features
    
    def split_data(self, X, y, test_size=0.2, random_state=42):
        """Split data into train and test sets"""
        print("\n--- Data Splitting ---")
        
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        print(f"✓ Train set: {self.X_train.shape[0]} records")
        print(f"✓ Test set: {self.X_test.shape[0]} records")
        
        return self.X_train, self.X_test, self.y_train, self.y_test
    
    def scale_features(self):
        """Standardize features using StandardScaler"""
        print("\n--- Feature Scaling ---")
        
        self.scaler = StandardScaler()
        self.X_train = self.scaler.fit_transform(self.X_train)
        self.X_test = self.scaler.transform(self.X_test)
        
        print("✓ Features scaled using StandardScaler")
        
        return self.X_train, self.X_test
    
    def train_knn(self, n_neighbors=7, metric='euclidean', weights='uniform'):
        """Train KNN model"""
        print("\n--- Model Training ---")
        print(f"KNN Parameters: k={n_neighbors}, metric={metric}, weights={weights}")
        
        self.model = KNeighborsClassifier(n_neighbors=n_neighbors, metric=metric, weights=weights)
        self.model.fit(self.X_train, self.y_train)
        
        print("✓ KNN model trained successfully")
        
        return self.model
    
    def evaluate_model(self):
        """Evaluate model performance"""
        print("\n--- Model Evaluation ---")
        
        y_train_pred = self.model.predict(self.X_train)
        y_test_pred = self.model.predict(self.X_test)
        
        train_acc = accuracy_score(self.y_train, y_train_pred)
        test_acc = accuracy_score(self.y_test, y_test_pred)
        precision = precision_score(self.y_test, y_test_pred)
        recall = recall_score(self.y_test, y_test_pred)
        f1 = f1_score(self.y_test, y_test_pred)
        
        self.evaluation_results = {
            'train_accuracy': train_acc,
            'test_accuracy': test_acc,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': confusion_matrix(self.y_test, y_test_pred),
            'classification_report': classification_report(self.y_test, y_test_pred)
        }
        
        print(f"✓ Train Accuracy: {train_acc:.4f}")
        print(f"✓ Test Accuracy: {test_acc:.4f}")
        print(f"✓ Precision: {precision:.4f}")
        print(f"✓ Recall: {recall:.4f}")
        print(f"✓ F1-Score: {f1:.4f}")
        print(f"\nConfusion Matrix:\n{self.evaluation_results['confusion_matrix']}")
        print(f"\nClassification Report:\n{self.evaluation_results['classification_report']}")
        
        return self.evaluation_results
    
    def save_model(self, filepath='heart_disease_model.pkl'):
        """Save trained model and scaler"""
        print(f"\n--- Saving Model ---")
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'evaluation_results': self.evaluation_results
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"✓ Model saved to {filepath}")
    
    def load_model(self, filepath='heart_disease_model.pkl'):
        """Load trained model and scaler"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        
        print(f"✓ Model loaded from {filepath}")
        
        return model_data
    
    def predict_single(self, user_data):
        """Predict for a single user"""
        user_df = pd.DataFrame([user_data])
        X_user = user_df[self.feature_names].copy()
        X_user_scaled = self.scaler.transform(X_user)
        
        prediction = self.model.predict(X_user_scaled)[0]
        probability = self.model.predict_proba(X_user_scaled)[0]
        
        engineered_features = {}
        if 'riskFactorCount' in user_data:
            engineered_features['riskFactorCount'] = user_data.get('riskFactorCount', 0)
        
        return prediction, probability, engineered_features