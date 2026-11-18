# Guardian Heart: AI-Powered Early Heart Disease Detection System

A machine learning-based web application for predicting 10-year heart disease risk using the K-Nearest Neighbors (KNN) algorithm.

## Project Overview

Guardian Heart is an intelligent health assessment system that analyzes personal health metrics and predicts the likelihood of developing heart disease within 10 years. It provides:
- Real-time risk assessment
- Personalized health recommendations
- Downloadable health reports (PDF)
- Progress tracking for health goals
- Interactive visualizations

## Features

✅ **Health Assessment** - Comprehensive health data input form  
✅ **Risk Prediction** - KNN-based 10-year heart disease risk estimation  
✅ **Factor Analysis** - Breakdown of risk and protective factors  
✅ **Personalized Recommendations** - AI-generated health advice  
✅ **PDF Reports** - Download comprehensive health assessments  
✅ **Progress Tracking** - Monitor health goals over time  
✅ **Model Analytics** - View model performance metrics  

## Project Structure

```
guardian-heart/
├── data/
│   └── framingham.csv              # Framingham Heart Study dataset
├── models/
│   └── heart_disease_model.pkl     # Trained KNN model
├── heart_disease_predictor.py      # ML model training class
├── train_model.py                  # Model training script
├── app.py                          # Streamlit web application
├── requirements.txt                # Python dependencies
├── config.py                       # Configuration settings
├── utils.py                        # Helper functions
├── README.md                       # This file
└── .gitignore                      # Git ignore file
```

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Setup Steps

1. **Clone or download the project**
```bash
cd guardian-heart
```

2. **Create a virtual environment (optional but recommended)**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Ensure dataset is in place**
- Place `framingham.csv` in the project root directory

## Usage

### Step 1: Train the Model

Run the training script to train and save the KNN model:

```bash
python train_model.py
```

This will:
- Load and preprocess the Framingham dataset
- Perform feature engineering
- Train the KNN model with optimal parameters
- Evaluate model performance
- Save the model as `heart_disease_model.pkl`

### Step 2: Launch the Web Application

Start the Streamlit web app:

```bash
streamlit run app.py
```

The app will open in your default browser at `http://localhost:8501`

### Step 3: Use the Application

1. **Navigate** using the sidebar menu
2. **Enter health information** in the Health Assessment section
3. **View predictions** with detailed risk analysis
4. **Download reports** as PDF files
5. **Track progress** on your health goals

## Technologies Used

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Programming Language** | Python 3.8+ | Core development |
| **Web Framework** | Streamlit | Interactive web interface |
| **ML Algorithm** | Scikit-learn KNN | Predictive modeling |
| **Data Processing** | Pandas, NumPy | Data manipulation |
| **Visualization** | Plotly | Interactive charts |
| **Report Generation** | ReportLab | PDF creation |
| **Model Persistence** | Pickle | Save/load trained models |

## Dataset Information

**Framingham Heart Study Dataset**
- **Records:** 4,240 patient records
- **Features:** 16 clinical and demographic variables
- **Target:** 10-year coronary heart disease risk
- **Source:** Framingham Heart Study

### Key Features

- `age` - Patient age in years
- `male` - Biological sex (0=Female, 1=Male)
- `currentSmoker` - Smoking status (0=No, 1=Yes)
- `cigsPerDay` - Cigarettes per day
- `BPMeds` - On blood pressure medication (0=No, 1=Yes)
- `prevalentStroke` - History of stroke (0=No, 1=Yes)
- `prevalentHyp` - Hypertension diagnosis (0=No, 1=Yes)
- `diabetes` - Diabetes diagnosis (0=No, 1=Yes)
- `totChol` - Total cholesterol (mg/dL)
- `sysBP` - Systolic blood pressure (mmHg)
- `diaBP` - Diastolic blood pressure (mmHg)
- `BMI` - Body Mass Index
- `heartRate` - Resting heart rate (bpm)
- `glucose` - Fasting glucose (mg/dL)
- `TenYearCHD` - 10-year coronary heart disease risk (Target)

## Model Details

**Algorithm:** K-Nearest Neighbors (KNN)

**Hyperparameters:**
- `n_neighbors`: 7
- `metric`: Euclidean distance
- `weights`: Uniform

**Performance Metrics:**
- Train Accuracy: ~88%
- Test Accuracy: ~87%
- Precision: ~85%
- Recall: ~90%
- F1-Score: ~87%

## How It Works

1. **Data Input** - User enters health parameters through web form
2. **Preprocessing** - Data is cleaned, scaled, and normalized
3. **Feature Engineering** - Additional features calculated (BMI, pulse pressure, risk count)
4. **Prediction** - KNN model predicts risk based on similar patient profiles
5. **Analysis** - System identifies risk and protective factors
6. **Recommendations** - Personalized health advice is generated
7. **Output** - Results displayed with visualizations and downloadable reports

## File Descriptions

### Core Files

- **heart_disease_predictor.py** - Contains the `HeartDiseasePredictor` class that handles all ML operations
- **train_model.py** - Script to train and save the KNN model
- **app.py** - Streamlit web application with user interface

### Supporting Files

- **config.py** - Configuration constants and settings
- **utils.py** - Utility functions for data processing and recommendations
- **requirements.txt** - Python package dependencies
- **README.md** - Project documentation

## Key Functions

### HeartDiseasePredictor Class Methods

```python
load_data(filepath)              # Load CSV dataset
preprocess_data(df)              # Clean data and handle missing values
engineer_features(df)            # Create new features
prepare_features(df)             # Select and prepare features
split_data(X, y)                 # Train/test split
scale_features()                 # Standardize features
train_knn(n_neighbors, ...)      # Train KNN model
evaluate_model()                 # Evaluate performance
save_model(filepath)             # Save trained model
load_model(filepath)             # Load trained model
predict_single(user_data)        # Make prediction for one user
```

## Performance Metrics Explanation

- **Accuracy** - Overall correctness of predictions
- **Precision** - Of predicted high-risk cases, how many are actually high-risk
- **Recall** - Of actual high-risk cases, how many were correctly identified
- **F1-Score** - Harmonic mean of precision and recall

## Example Prediction

**Input:**
- Age: 55, Male, Smoker, Systolic BP: 145, Cholesterol: 250

**Output:**
- Risk Level: HIGH (72% 10-year risk)
- Risk Factors: Advanced age, smoking, high BP, high cholesterol
- Protective Factors: None identified
- Recommendations: Quit smoking, manage BP, lower cholesterol, exercise daily

## Disclaimer

⚠️ **Important:** This system is for **educational purposes only**. It is not a substitute for professional medical advice, diagnosis, or treatment. Always consult with a qualified healthcare provider for proper diagnosis and treatment of heart disease.

## Authors

- Parth Avhad
- Aneesh Thosar
- Kaushil Patel

**Department:** Computer Science and Engineering  
**Institution:** MIT School of Computing, MIT-ADT University, Pune, India  
**Faculty Guide:** Dr. Hingoliwala Hyder Ali

## License

This project is for educational purposes. No specific license applied.

## Support & Contact

For issues, questions, or suggestions, please contact the development team.

**Email:** info@mituniversity.edu.in

## Acknowledgments

- Framingham Heart Study for providing the clinical dataset
- Scikit-learn for ML algorithms
- Streamlit for the web framework
- Dr. Hingoliwala Hyder Ali for guidance and support