# Configuration Settings for Guardian Heart Project

# Model Parameters
KNN_N_NEIGHBORS = 7
KNN_METRIC = 'euclidean'
KNN_WEIGHTS = 'uniform'

# Data Parameters
TEST_SIZE = 0.2
RANDOM_STATE = 42
STRATIFIED = True

# Feature Names (Core Features)
CORE_FEATURES = [
    'male', 'age', 'education', 'currentSmoker', 'cigsPerDay',
    'BPMeds', 'prevalentStroke', 'prevalentHyp', 'diabetes',
    'totChol', 'sysBP', 'diaBP', 'BMI', 'heartRate', 'glucose'
]

# Engineered Features
ENGINEERED_FEATURES = [
    'pulsePressure',
    'ageGroup',
    'riskFactorCount'
]

# File Paths
DATA_FILE = 'framingham.csv'
MODEL_FILE = 'heart_disease_model.pkl'
TARGET_COLUMN = 'TenYearCHD'

# Risk Categories
RISK_THRESHOLDS = {
    'LOW': 0.33,
    'MEDIUM': 0.66,
    'HIGH': 1.0
}

# Health Ranges
BMI_RANGES = {
    'Underweight': (0, 18.5),
    'Normal': (18.5, 25),
    'Overweight': (25, 30),
    'Obese': (30, float('inf'))
}

BP_RANGES = {
    'Normal': (0, 120, 80),
    'Elevated': (120, 130, 80),
    'Stage 1': (130, 140, 90),
    'Stage 2': (140, float('inf'), 90)
}

CHOLESTEROL_RANGES = {
    'Desirable': (0, 200),
    'Borderline High': (200, 240),
    'High': (240, float('inf'))
}

GLUCOSE_RANGES = {
    'Normal': (0, 100),
    'Pre-diabetic': (100, 126),
    'Diabetic': (126, float('inf'))
}

# App Settings
APP_TITLE = "Guardian Heart - AI-Powered Early Heart Disease Detection System"
APP_ICON = "❤️"

# Disclaimer Text
MEDICAL_DISCLAIMER = """
⚠️ **Medical Disclaimer:**
This tool is for educational purposes only. It is not a substitute for professional medical advice, 
diagnosis, or treatment. Always consult with a qualified healthcare provider for proper diagnosis and 
treatment of heart disease.
"""

# Recommendations Priority Levels
PRIORITY_LEVELS = {
    'HIGHEST': '🔴',
    'HIGH': '🟠',
    'MEDIUM': '🟡',
    'LOW': '🟢'
}