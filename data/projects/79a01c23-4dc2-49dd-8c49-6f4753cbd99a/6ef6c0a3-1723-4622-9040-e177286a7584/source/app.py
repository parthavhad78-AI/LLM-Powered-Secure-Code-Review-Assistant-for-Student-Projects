import streamlit as st
import pandas as pd
import numpy as np
import pickle
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import io

# Page config
st.set_page_config(
    page_title="Guardian Heart - Heart Disease Detection",
    page_icon="❤️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Ultra Premium Styling
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

* {
    margin: 0;
    padding: 0;
    font-family: 'Inter', sans-serif;
}

html, body, [class*="css"] {
    background: linear-gradient(135deg, #0f0f1e 0%, #1a1a3f 50%, #0f1f3f 100%);
    color: #e0e0e0;
}

/* Main Container */
.main {
    background: transparent;
}

/* Header Section */
.header-container {
    background: linear-gradient(135deg, rgba(231, 76, 60, 0.95) 0%, rgba(192, 57, 43, 1) 50%, rgba(158, 27, 27, 0.95) 100%);
    padding: 3rem 2rem;
    border-radius: 20px;
    margin-bottom: 2rem;
    box-shadow: 0 20px 60px rgba(231, 76, 60, 0.4);
    text-align: center;
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.1);
    animation: slideDown 0.6s ease-out;
}

@keyframes slideDown {
    from {
        opacity: 0;
        transform: translateY(-20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.header-container h1 {
    font-size: 3rem;
    color: white;
    font-weight: 700;
    text-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    letter-spacing: -1px;
    margin-bottom: 0.5rem;
}

.header-container p {
    color: rgba(255, 255, 255, 0.95);
    font-size: 1.1rem;
    font-weight: 300;
    letter-spacing: 0.5px;
}

.header-subtitle {
    color: rgba(255, 255, 255, 0.8);
    font-size: 0.95rem;
    margin-top: 1rem;
    opacity: 0.9;
}

/* Input Section */
.input-section {
    background: linear-gradient(135deg, rgba(45, 52, 54, 0.7) 0%, rgba(30, 39, 46, 0.7) 100%);
    border: 1px solid rgba(231, 76, 60, 0.3);
    border-radius: 15px;
    padding: 2rem;
    margin: 1.5rem 0;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    backdrop-filter: blur(10px);
}

.input-label {
    font-weight: 600;
    color: #ecf0f1;
    font-size: 1.05rem;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

/* Card Styling */
.metric-card {
    background: linear-gradient(135deg, rgba(52, 73, 94, 0.5) 0%, rgba(44, 62, 80, 0.5) 100%);
    padding: 1.5rem;
    border-radius: 12px;
    border: 1px solid rgba(231, 76, 60, 0.2);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
    margin: 1rem 0;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    backdrop-filter: blur(10px);
}

.metric-card:hover {
    transform: translateY(-4px);
    border-color: rgba(231, 76, 60, 0.5);
    box-shadow: 0 12px 36px rgba(231, 76, 60, 0.15);
}

.metric-card-title {
    font-weight: 600;
    color: #e74c3c;
    font-size: 0.95rem;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.metric-card-value {
    font-size: 1.8rem;
    font-weight: 700;
    color: #ecf0f1;
    margin: 0.5rem 0;
}

.metric-card-subtitle {
    font-size: 0.85rem;
    color: #bdc3c7;
}

/* Risk Factor Cards */
.risk-factor {
    background: linear-gradient(135deg, rgba(231, 76, 60, 0.15) 0%, rgba(192, 57, 43, 0.1) 100%);
    border-left: 4px solid #e74c3c;
    border-radius: 10px;
    padding: 1.2rem;
    margin: 1rem 0;
    color: #ecf0f1;
    font-weight: 500;
    transition: all 0.3s ease;
    border: 1px solid rgba(231, 76, 60, 0.2);
}

.risk-factor:hover {
    border-color: #e74c3c;
    box-shadow: 0 8px 24px rgba(231, 76, 60, 0.15);
    transform: translateX(4px);
}

.risk-factor-label {
    color: #e74c3c;
    font-weight: 700;
    font-size: 1.1rem;
}

.risk-factor-value {
    color: #ecf0f1;
    font-size: 0.95rem;
    margin-top: 0.3rem;
}

/* Protective Factor Cards */
.protective-factor {
    background: linear-gradient(135deg, rgba(46, 213, 115, 0.15) 0%, rgba(39, 174, 96, 0.1) 100%);
    border-left: 4px solid #2ed573;
    border-radius: 10px;
    padding: 1.2rem;
    margin: 1rem 0;
    color: #ecf0f1;
    font-weight: 500;
    transition: all 0.3s ease;
    border: 1px solid rgba(46, 213, 115, 0.2);
}

.protective-factor:hover {
    border-color: #2ed573;
    box-shadow: 0 8px 24px rgba(46, 213, 115, 0.15);
    transform: translateX(4px);
}

.protective-factor-label {
    color: #2ed573;
    font-weight: 700;
    font-size: 1.1rem;
}

.protective-factor-value {
    color: #ecf0f1;
    font-size: 0.95rem;
    margin-top: 0.3rem;
}

/* Recommendation Box */
.recommendation-box {
    background: linear-gradient(135deg, rgba(52, 152, 219, 0.1) 0%, rgba(41, 128, 185, 0.05) 100%);
    border-left: 4px solid #3498db;
    border-radius: 10px;
    padding: 1.3rem;
    margin: 1rem 0;
    color: #ecf0f1;
    border: 1px solid rgba(52, 152, 219, 0.2);
    transition: all 0.3s ease;
}

.recommendation-box:hover {
    border-color: #3498db;
    box-shadow: 0 8px 24px rgba(52, 152, 219, 0.1);
}

.recommendation-priority {
    display: inline-block;
    padding: 0.3rem 0.8rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 0.5rem;
}

.priority-highest {
    background: #e74c3c;
    color: white;
}

.priority-high {
    background: #e67e22;
    color: white;
}

.priority-medium {
    background: #f39c12;
    color: white;
}

.priority-low {
    background: #27ae60;
    color: white;
}

.recommendation-title {
    color: #3498db;
    font-weight: 700;
    font-size: 1.1rem;
    margin-bottom: 0.3rem;
}

.recommendation-desc {
    font-size: 0.95rem;
    color: #bdc3c7;
    margin-bottom: 0.5rem;
}

.recommendation-action {
    font-size: 0.9rem;
    color: #95a5a6;
    font-style: italic;
    margin-top: 0.5rem;
}

/* Status Badges */
.status-low-risk {
    background: linear-gradient(135deg, rgba(46, 213, 115, 0.2) 0%, rgba(39, 174, 96, 0.15) 100%);
    border: 2px solid #2ed573;
    color: #2ed573;
    padding: 1.5rem;
    border-radius: 12px;
    text-align: center;
    font-weight: 600;
    font-size: 1.3rem;
    margin: 1.5rem 0;
    transition: all 0.3s ease;
}

.status-low-risk:hover {
    box-shadow: 0 12px 36px rgba(46, 213, 115, 0.2);
    transform: scale(1.02);
}

.status-high-risk {
    background: linear-gradient(135deg, rgba(231, 76, 60, 0.2) 0%, rgba(192, 57, 43, 0.15) 100%);
    border: 2px solid #e74c3c;
    color: #e74c3c;
    padding: 1.5rem;
    border-radius: 12px;
    text-align: center;
    font-weight: 600;
    font-size: 1.3rem;
    margin: 1.5rem 0;
    transition: all 0.3s ease;
}

.status-high-risk:hover {
    box-shadow: 0 12px 36px rgba(231, 76, 60, 0.2);
    transform: scale(1.02);
}

/* Button Styling */
.stButton > button {
    background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%) !important;
    color: white !important;
    border: none !important;
    padding: 0.8rem 2rem !important;
    border-radius: 10px !important;
    font-weight: 600 !important;
    font-size: 1rem !important;
    transition: all 0.3s ease !important;
    box-shadow: 0 8px 24px rgba(231, 76, 60, 0.3) !important;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    width: 100% !important;
}

.stButton > button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 12px 36px rgba(231, 76, 60, 0.4) !important;
}

.stButton > button:active {
    transform: translateY(0) !important;
}

/* Section Headers */
.section-header {
    border-bottom: 3px solid #e74c3c;
    padding-bottom: 1rem;
    margin: 2rem 0 1.5rem 0;
    color: #ecf0f1;
    font-size: 1.5rem;
    font-weight: 700;
}

/* Info Box */
.info-box {
    background: linear-gradient(135deg, rgba(52, 152, 219, 0.1) 0%, rgba(41, 128, 185, 0.05) 100%);
    border: 1px solid #3498db;
    padding: 1rem;
    border-radius: 10px;
    margin: 1rem 0;
    color: #bdc3c7;
    border-left: 4px solid #3498db;
}

/* Success Box */
.success-box {
    background: linear-gradient(135deg, rgba(46, 213, 115, 0.1) 0%, rgba(39, 174, 96, 0.05) 100%);
    border: 1px solid #2ed573;
    padding: 1rem;
    border-radius: 10px;
    margin: 1rem 0;
    color: #2ed573;
    border-left: 4px solid #2ed573;
}

/* Warning Box */
.warning-box {
    background: linear-gradient(135deg, rgba(241, 196, 15, 0.1) 0%, rgba(183, 149, 11, 0.05) 100%);
    border: 1px solid #f1c40f;
    padding: 1rem;
    border-radius: 10px;
    margin: 1rem 0;
    color: #ecf0f1;
    border-left: 4px solid #f1c40f;
}

/* Help Text */
.help-text {
    font-size: 0.85rem;
    color: #95a5a6;
    font-style: italic;
    margin-top: -8px;
    margin-bottom: 12px;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, rgba(26, 26, 46, 0.9) 0%, rgba(22, 33, 62, 0.9) 100%);
    border-right: 1px solid rgba(231, 76, 60, 0.2);
}

/* Divider */
hr {
    border: none;
    height: 1px;
    background: linear-gradient(90deg, transparent 0%, rgba(231, 76, 60, 0.3) 50%, transparent 100%);
    margin: 2rem 0;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 1rem;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 10px;
}

/* Metric Widget */
.stMetric {
    background: linear-gradient(135deg, rgba(52, 73, 94, 0.5) 0%, rgba(44, 62, 80, 0.5) 100%);
    padding: 1.5rem;
    border-radius: 12px;
    border: 1px solid rgba(231, 76, 60, 0.2);
}

</style>
""", unsafe_allow_html=True)

# Load Model
@st.cache_resource
def load_model():
    try:
        with open('heart_disease_model.pkl', 'rb') as f:
            return pickle.load(f)
    except FileNotFoundError:
        return None

@st.cache_data
def load_data():
    for name in ['framingham.csv', 'cardio_train.csv']:
        try:
            return pd.read_csv(name)
        except:
            continue
    return None

# Helper Functions
def calculate_bmi(weight_kg, height_cm):
    return weight_kg / ((height_cm / 100) ** 2)

def get_bmi_category(bmi):
    if bmi < 18.5:
        return "Underweight", "🔵", "May indicate malnutrition"
    elif bmi < 25:
        return "Normal weight", "🟢", "Optimal weight range"
    elif bmi < 30:
        return "Overweight", "🟡", "Increased heart disease risk"
    else:
        return "Obese", "🔴", "Significantly increased risk"

def get_bp_category(sys, dia):
    if sys < 120 and dia < 80:
        return "Normal", "🟢", "Optimal blood pressure"
    elif sys < 130:
        return "Elevated", "🟡", "Monitor regularly"
    elif sys < 140 or dia < 90:
        return "Stage 1 High", "🟠", "Lifestyle changes recommended"
    else:
        return "Stage 2 High", "🔴", "Medical intervention needed"

def get_cholesterol_category(chol):
    if chol < 200:
        return "Desirable", "🟢", "Optimal level"
    elif chol < 240:
        return "Borderline High", "🟡", "Monitor and improve diet"
    else:
        return "High", "🔴", "Medical attention recommended"

def get_recommendations(user_data):
    recs = []
    
    if user_data.get('currentSmoker') == 1:
        recs.append(("HIGHEST", "🔴 Quit Smoking", "Smoking is the top modifiable risk factor. Quitting reduces risk by 50% within 1 year.", "Start nicotine replacement therapy or consult a smoking cessation program."))
    
    if user_data.get('sysBP', 0) > 140 or user_data.get('diaBP', 0) > 90:
        recs.append(("HIGH", "🟠 Manage Blood Pressure", "Your BP is elevated. Control through diet, exercise, and medication if needed.", "Reduce salt intake, exercise 30 mins daily, monitor BP regularly."))
    
    if user_data.get('totChol', 0) > 240:
        recs.append(("HIGH", "🟠 Lower Cholesterol", "High cholesterol increases heart disease risk significantly.", "Eat heart-healthy foods (fish, nuts, whole grains), reduce saturated fats."))
    
    if user_data.get('BMI', 0) > 30:
        recs.append(("HIGH", "🟠 Weight Management", "Weight loss can significantly reduce your risk.", "Aim for 5-10% weight loss through diet and exercise."))
    
    if user_data.get('diabetes') == 1:
        recs.append(("HIGH", "🟠 Manage Diabetes", "Diabetics have 2-4x higher heart disease risk.", "Monitor blood glucose, take medications as prescribed, eat balanced meals."))
    
    if user_data.get('glucose', 0) > 125:
        recs.append(("MEDIUM", "🟡 Control Blood Sugar", "Pre-diabetic glucose levels need attention.", "Reduce refined sugars, increase fiber, maintain healthy weight."))
    
    recs.append(("MEDIUM", "🟡 Exercise Regularly", "Physical activity strengthens your heart.", "150 minutes of moderate aerobic exercise per week is recommended."))
    recs.append(("MEDIUM", "🟡 Healthy Diet", "Nutrition is key to heart health.", "Follow Mediterranean or DASH diet, reduce processed foods."))
    recs.append(("LOW", "🟢 Stress Management", "Chronic stress increases heart disease risk.", "Practice meditation, yoga, or deep breathing exercises."))
    recs.append(("LOW", "🟢 Regular Checkups", "Monitor your health consistently.", "Schedule annual heart health screening with your doctor."))
    
    return recs

def generate_pdf_report(user_data, prediction, probability, risk_factors, protective_factors):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=20, 
                                textColor=colors.HexColor('#e74c3c'), alignment=1)
    
    elements.append(Paragraph("❤️ Guardian Heart Health Report", title_style))
    elements.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 0.3*inch))
    
    elements.append(Paragraph("10-Year Heart Disease Risk Assessment", styles['Heading2']))
    risk_text = f"<b>Risk Level:</b> {'HIGH RISK ⚠️' if prediction == 1 else 'LOW RISK ✅'}<br/>"
    risk_text += f"<b>Risk Probability:</b> {probability[1]:.1%}"
    elements.append(Paragraph(risk_text, styles['Normal']))
    elements.append(Spacer(1, 0.2*inch))
    
    if risk_factors:
        elements.append(Paragraph("Risk Factors", styles['Heading2']))
        risk_data = [[factor, str(value)] for factor, value, _ in risk_factors]
        risk_table = Table(risk_data)
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        elements.append(risk_table)
    
    doc.build(elements)
    buffer.seek(0)
    return buffer

# Main Application
st.markdown("""
<div class="header-container">
    <h1>❤️ Guardian Heart</h1>
    <p>AI-Powered Early Heart Disease Detection System</p>
    <p class="header-subtitle">Estimate your 10-year heart disease risk with advanced machine learning</p>
</div>
""", unsafe_allow_html=True)

model_data = load_model()
data = load_data()

if model_data is None:
    st.error("⚠️ Model not found. Please run train_model.py first.")
    st.stop()

# Sidebar Navigation
with st.sidebar:
    st.title("🧭 Navigation")
    st.markdown("---")
    page = st.selectbox(
        "Choose a section:",
        ["🩺 Health Assessment", "📊 Progress Tracker", "💡 Recommendations", "📈 Analytics", "ℹ️ About"],
        index=0
    )

# Page: Health Assessment
if page == "🩺 Health Assessment":
    st.markdown('<h2 class="section-header">🩺 Comprehensive Heart Disease Risk Assessment</h2>', unsafe_allow_html=True)
    
    st.markdown("""
    <div class="warning-box">
    ⚠️ <b>Medical Disclaimer:</b> This tool is for educational use only. It is not a substitute for professional medical advice, diagnosis, or treatment.
    </div>
    """, unsafe_allow_html=True)
    
    # Create tabs for better organization
    tab1, tab2 = st.tabs(["📋 Personal & Lifestyle", "💉 Vitals & Labs"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown('<div class="input-section"><div class="input-label">👤 Personal Information</div>', unsafe_allow_html=True)
            
            age = st.slider("Age", 30, 80, 50, help="Your current age in years")
            st.markdown('<div class="help-text">Risk increases with age.</div>', unsafe_allow_html=True)
            
            gender_options = {"Female": 0, "Male": 1}
            gender_selection = st.selectbox("Biological Sex", list(gender_options.keys()), help="Biological sex affects risk levels")
            male = gender_options[gender_selection]
            
            education_options = {"< High School": 1, "High School": 2, "Some College": 3, "College": 4}
            education_selection = st.selectbox("Education Level", list(education_options.keys()))
            education = education_options[education_selection]
            
            st.markdown('</div>', unsafe_allow_html=True)
            
            st.markdown('<div class="input-section"><div class="input-label">🚬 Lifestyle Factors</div>', unsafe_allow_html=True)
            
            smoking_options = {"No, I don't smoke": 0, "Yes, I currently smoke": 1}
            smoking_selection = st.selectbox("Do you currently smoke?", list(smoking_options.keys()))
            currentSmoker = smoking_options[smoking_selection]
            
            cigsPerDay = 0
            if currentSmoker:
                cigsPerDay = st.slider("Cigarettes per day", 1, 60, 10)
            else:
                st.markdown('<div class="success-box">✅ Great! Not smoking significantly reduces your risk.</div>', unsafe_allow_html=True)
            
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col2:
            st.markdown('<div class="input-section"><div class="input-label">🏥 Medical History</div>', unsafe_allow_html=True)
            
            diabetes_options = {"No": 0, "Yes": 1}
            diabetes = st.selectbox("Diabetes", list(diabetes_options.keys())) 
            diabetes = diabetes_options[diabetes]
            
            stroke_options = {"No": 0, "Yes": 1}
            prevalentStroke = st.selectbox("Previous Stroke", list(stroke_options.keys()))
            prevalentStroke = stroke_options[prevalentStroke]
            
            hypertension_options = {"No": 0, "Yes": 1}
            prevalentHyp = st.selectbox("Hypertension (High BP)", list(hypertension_options.keys()))
            prevalentHyp = hypertension_options[prevalentHyp]
            
            bp_meds_options = {"No": 0, "Yes": 1}
            BPMeds = st.selectbox("BP Medication", list(bp_meds_options.keys()))
            BPMeds = bp_meds_options[BPMeds]
            
            st.markdown('</div>', unsafe_allow_html=True)
    
    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown('<div class="input-section"><div class="input-label">📏 Body Measurements</div>', unsafe_allow_html=True)
            
            height_cm = st.slider("Height (cm)", 140, 200, 170)
            weight_kg = st.slider("Weight (kg)", 40, 150, 70)
            bmi = calculate_bmi(weight_kg, height_cm)
            bmi_cat, bmi_emoji, bmi_note = get_bmi_category(bmi)
            
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-card-title">{bmi_emoji} BMI Status</div>
                <div class="metric-card-value">{bmi:.1f}</div>
                <div class="metric-card-subtitle">{bmi_cat} - {bmi_note}</div>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown('</div>', unsafe_allow_html=True)
            
            st.markdown('<div class="input-section"><div class="input-label">💓 Heart & Circulation</div>', unsafe_allow_html=True)
            
            heartRate = st.slider("Resting Heart Rate (bpm)", 50, 120, 70)
            if heartRate < 60:
                st.markdown('<div class="success-box">✅ Low resting heart rate indicates good fitness.</div>', unsafe_allow_html=True)
            elif heartRate > 100:
                st.markdown('<div class="warning-box">⚠️ High resting heart rate—consider a checkup.</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="success-box">✅ Normal resting heart rate.</div>', unsafe_allow_html=True)
            
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col2:
            st.markdown('<div class="input-section"><div class="input-label">🩹 Blood Pressure</div>', unsafe_allow_html=True)
            
            sysBP = st.slider("Systolic BP (mmHg)", 90, 200, 120)
            diaBP = st.slider("Diastolic BP (mmHg)", 60, 120, 80)
            bp_cat, bp_emoji, bp_note = get_bp_category(sysBP, diaBP)
            
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-card-title">{bp_emoji} BP Status</div>
                <div class="metric-card-value">{sysBP}/{diaBP}</div>
                <div class="metric-card-subtitle">{bp_cat} - {bp_note}</div>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown('</div>', unsafe_allow_html=True)
            
            st.markdown('<div class="input-section"><div class="input-label">🧪 Laboratory Values</div>', unsafe_allow_html=True)
            
            totChol = st.slider("Total Cholesterol (mg/dL)", 120, 400, 200)
            chol_cat, chol_emoji, chol_note = get_cholesterol_category(totChol)
            
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-card-title">{chol_emoji} Cholesterol Status</div>
                <div class="metric-card-value">{totChol}</div>
                <div class="metric-card-subtitle">{chol_cat} - {chol_note}</div>
            </div>
            """, unsafe_allow_html=True)
            
            glucose = st.slider("Fasting Glucose (mg/dL)", 70, 200, 90)
            if glucose < 100:
                st.markdown('<div class="success-box">✅ Normal glucose level!</div>', unsafe_allow_html=True)
            elif glucose < 126:
                st.markdown('<div class="warning-box">⚠️ Pre-diabetic glucose—work on diet/lifestyle.</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="info-box">ℹ️ Diabetic range—see a doctor!</div>', unsafe_allow_html=True)
            
            st.markdown('</div>', unsafe_allow_html=True)
    
    # Prediction Button
    st.markdown("---")
    col_button = st.columns([1, 2, 1])
    with col_button[1]:
        if st.button("🔮 Calculate My 10-Year Heart Disease Risk", use_container_width=True):
            BMI = calculate_bmi(weight_kg, height_cm)
            pulsePressure = sysBP - diaBP
            riskFactorCount = currentSmoker + diabetes + prevalentStroke + prevalentHyp
            ageGroup = 1 if age < 40 else (2 if age < 50 else (3 if age < 60 else 4))
            
            user_data = {
                'male': male, 'age': age, 'education': education,
                'currentSmoker': currentSmoker, 'cigsPerDay': cigsPerDay,
                'BPMeds': BPMeds, 'prevalentStroke': prevalentStroke,
                'prevalentHyp': prevalentHyp, 'diabetes': diabetes,
                'totChol': totChol, 'sysBP': sysBP, 'diaBP': diaBP,
                'BMI': BMI, 'heartRate': heartRate, 'glucose': glucose,
                'pulsePressure': pulsePressure, 'ageGroup': ageGroup,
                'riskFactorCount': riskFactorCount
            }
            
            user_df = pd.DataFrame([user_data])
            X_user = user_df[model_data['feature_names']].copy()
            X_user_scaled = model_data['scaler'].transform(X_user)
            
            prediction = model_data['model'].predict(X_user_scaled)[0]
            probability = model_data['model'].predict_proba(X_user_scaled)[0]
            
            # Results
            st.markdown("---")
            st.markdown('<h2 class="section-header">🎯 Your Heart Disease Risk Assessment</h2>', unsafe_allow_html=True)
            
            if prediction == 1:
                st.markdown(f"""
                <div class="status-high-risk">
                    ⚠️ HIGH RISK: {probability[1]:.1%} 10-year risk
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="status-low-risk">
                    ✅ LOW RISK: {probability[1]:.1%} 10-year risk
                </div>
                """, unsafe_allow_html=True)
            
            # Detailed Analysis
            st.markdown('<h3>📊 Detailed Risk Analysis</h3>', unsafe_allow_html=True)
            metric_col1, metric_col2, metric_col3 = st.columns(3)
            with metric_col1:
                st.metric("Low Risk Probability", f"{probability[0]:.1%}")
            with metric_col2:
                st.metric("High Risk Probability", f"{probability[1]:.1%}")
            with metric_col3:
                st.metric("Risk Factors Present", int(riskFactorCount))
            
            # Risk and Protective Factors
            risk_factors = []
            protective_factors = []
            
            if age > 55:
                risk_factors.append(("Advanced Age", f"{age} years", ""))
            if male:
                risk_factors.append(("Male Gender", "Biological male", "Men have 2-3x higher risk"))
            else:
                protective_factors.append(("Female Gender", "Biological female", "Lower risk before menopause"))
            if BMI >= 30:
                risk_factors.append(("Obesity", f"BMI {BMI:.1f}", "Significantly increased risk"))
            elif BMI < 25:
                protective_factors.append(("Healthy Weight", f"BMI {BMI:.1f}", "Optimal weight range"))
            if sysBP > 140:
                risk_factors.append(("High BP", f"{sysBP}/{diaBP} mmHg", "Major modifiable risk factor"))
            if totChol > 240:
                risk_factors.append(("High Cholesterol", f"{totChol} mg/dL", "Increases plaque buildup"))
            if currentSmoker:
                risk_factors.append(("Current Smoker", f"{cigsPerDay} cigs/day", "Top modifiable risk factor"))
            else:
                protective_factors.append(("Non-smoker", "No tobacco use", "Excellent for cardiovascular health"))
            if diabetes:
                risk_factors.append(("Diabetes", "Yes", "2-4x increased risk"))
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown('<h4>⚠️ Risk Factors Present</h4>', unsafe_allow_html=True)
                if risk_factors:
                    for factor, val, desc in risk_factors:
                        st.markdown(f"""
                        <div class="risk-factor">
                            <div class="risk-factor-label">{factor}</div>
                            <div class="risk-factor-value">{val}</div>
                            <small>{desc}</small>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.markdown('<div class="success-box">🎉 No major risk factors identified!</div>', unsafe_allow_html=True)
            
            with col2:
                st.markdown('<h4>✅ Protective Factors</h4>', unsafe_allow_html=True)
                if protective_factors:
                    for factor, val, desc in protective_factors:
                        st.markdown(f"""
                        <div class="protective-factor">
                            <div class="protective-factor-label">{factor}</div>
                            <div class="protective-factor-value">{val}</div>
                            <small>{desc}</small>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.markdown('<div class="info-box">ℹ️ Focus on developing protective factors through lifestyle changes.</div>', unsafe_allow_html=True)
            
            # Personalized Recommendations
            st.markdown("---")
            st.markdown('<h2 class="section-header">💡 Personalized Health Recommendations</h2>', unsafe_allow_html=True)
            recommendations = get_recommendations(user_data)
            
            for priority, title, desc, action in recommendations:
                priority_class = f"priority-{priority.lower()}"
                st.markdown(f"""
                <div class="recommendation-box">
                    <span class="recommendation-priority {priority_class}">{priority}</span>
                    <div class="recommendation-title">{title}</div>
                    <div class="recommendation-desc">{desc}</div>
                    <div class="recommendation-action">💡 {action}</div>
                </div>
                """, unsafe_allow_html=True)
            
            # Download PDF
            st.markdown("---")
            st.markdown('<h3>📥 Download Your Health Report</h3>', unsafe_allow_html=True)
            pdf_buffer = generate_pdf_report(user_data, prediction, probability, risk_factors, protective_factors)
            st.download_button(
                label="📄 Download PDF Report",
                data=pdf_buffer.getvalue(),
                file_name=f"Guardian_Heart_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
                use_container_width=True
            )

elif page == "📊 Progress Tracker":
    st.markdown('<h2 class="section-header">📊 Health Goals & Progress Tracker</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 1])
    with col1:
        goal = st.selectbox("Select Your Health Goal", 
            ["Quit Smoking", "Manage BP", "Lower Cholesterol", "Weight Loss", "Blood Sugar Control"])
    
    with col2:
        progress = st.slider("Progress %", 0, 100, 0)
    
    st.markdown(f'<div class="goal-box" style="text-align:center; font-size: 1.5rem;"><strong>Current Progress: {progress}%</strong></div>', unsafe_allow_html=True)
    
    if st.button("💾 Save Progress", use_container_width=True):
        st.success(f"✅ Progress saved! You're {progress}% towards your {goal} goal.")
    
    weeks = list(range(1, 9))
    progress_data = [10 + i*10 for i in range(8)]
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=weeks, y=progress_data, mode='lines+markers', 
                            name='Progress %', 
                            line=dict(color='#e74c3c', width=4),
                            marker=dict(size=12, color='#e74c3c', symbol='circle')))
    fig.update_layout(
        title=f"Your {goal} Progress - 8 Week Journey",
        xaxis_title="Week",
        yaxis_title="Progress (%)",
        template="plotly_dark",
        height=450,
        hovermode='x unified',
        showlegend=False
    )
    st.plotly_chart(fig, use_container_width=True)

elif page == "💡 Recommendations":
    st.markdown('<h2 class="section-header">💡 General Health Recommendations</h2>', unsafe_allow_html=True)
    
    sample_data = {'currentSmoker': 0, 'sysBP': 130, 'diaBP': 85, 'totChol': 220, 'BMI': 26, 'diabetes': 0, 'glucose': 100}
    recs = get_recommendations(sample_data)
    
    for priority, title, desc, action in recs:
        priority_class = f"priority-{priority.lower()}"
        st.markdown(f"""
        <div class="recommendation-box">
            <span class="recommendation-priority {priority_class}">{priority}</span>
            <div class="recommendation-title">{title}</div>
            <div class="recommendation-desc">{desc}</div>
            <div class="recommendation-action">💡 {action}</div>
        </div>
        """, unsafe_allow_html=True)

elif page == "📈 Analytics":
    st.markdown('<h2 class="section-header">📈 Model Performance & Analytics</h2>', unsafe_allow_html=True)
    if 'evaluation_results' in model_data:
        results = model_data['evaluation_results']
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("🎯 Accuracy", f"{results['test_accuracy']:.1%}")
        col2.metric("✅ Precision", f"{results['precision']:.1%}")
        col3.metric("🔍 Recall", f"{results['recall']:.1%}")
        col4.metric("📊 F1-Score", f"{results['f1_score']:.1%}")

else:  # About
    st.markdown("""
    <div class="info-box">
    
    # ❤️ About Guardian Heart
    
    **Guardian Heart** is an AI-powered intelligent health assessment system designed for early heart disease detection and prevention.
    
    ## 🎯 Our Mission
    To provide accessible, accurate, and actionable cardiovascular health insights to empower individuals in making informed health decisions.
    
    ## 🔧 Technology Stack
    - **Machine Learning Algorithm:** K-Nearest Neighbors (KNN) with ensemble optimization
    - **Clinical Dataset:** Framingham Heart Study (4,240+ patient records)
    - **Platform:** Streamlit Web Application
    - **Data Science:** Python, Scikit-learn, Pandas
    
    ## ✨ Key Features
    ✅ Real-time risk assessment  
    ✅ Personalized recommendations  
    ✅ Progress tracking  
    ✅ PDF report generation  
    ✅ Interactive visualizations  
    ✅ Detailed factor analysis  
    
    ## ⚠️ Important Disclaimer
    This system is for **educational and informational purposes only**. It is not a substitute for professional medical advice, diagnosis, or treatment. Always consult with a qualified healthcare provider for medical decisions.
    
    ## 👥 Development Team
    - **Parth Avhad**
    - **Aneesh Thosar**
    - **Kaushil Patel**
    
    **Faculty Guide:** Dr. Hingoliwala Hyder Ali  
    **Institution:** MIT School of Computing, MIT-ADT University, Pune
    
    </div>
    """, unsafe_allow_html=True)