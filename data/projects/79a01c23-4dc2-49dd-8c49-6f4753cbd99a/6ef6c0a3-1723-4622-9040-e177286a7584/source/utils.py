"""
Utility functions for Guardian Heart project
"""

def calculate_bmi(weight_kg, height_cm):
    """Calculate Body Mass Index"""
    height_m = height_cm / 100
    return weight_kg / (height_m ** 2)

def get_bmi_category(bmi):
    """Get BMI category and emoji"""
    if bmi < 18.5:
        return "Underweight", "🔵", "May indicate malnutrition"
    elif bmi < 25:
        return "Normal weight", "🟢", "Optimal weight range"
    elif bmi < 30:
        return "Overweight", "🟡", "Increased heart disease risk"
    else:
        return "Obese", "🔴", "Significantly increased risk"

def get_bp_category(systolic, diastolic):
    """Get Blood Pressure category and emoji"""
    if systolic < 120 and diastolic < 80:
        return "Normal", "🟢", "Optimal blood pressure"
    elif systolic < 130 and diastolic < 80:
        return "Elevated", "🟡", "Monitor regularly"
    elif systolic < 140 or diastolic < 90:
        return "Stage 1 High", "🟠", "Lifestyle changes recommended"
    else:
        return "Stage 2 High", "🔴", "Medical intervention needed"

def get_cholesterol_category(cholesterol):
    """Get Cholesterol category and emoji"""
    if cholesterol < 200:
        return "Desirable", "🟢", "Optimal level"
    elif cholesterol < 240:
        return "Borderline High", "🟡", "Monitor and improve diet"
    else:
        return "High", "🔴", "Medical attention recommended"

def get_glucose_category(glucose):
    """Get Glucose category and emoji"""
    if glucose < 100:
        return "Normal", "🟢", "Good metabolic health"
    elif glucose < 126:
        return "Pre-diabetic", "🟡", "Increased cardiovascular risk"
    else:
        return "Diabetic", "🔴", "High glucose damages blood vessels"

def get_risk_level_emoji(probability):
    """Get emoji based on risk probability"""
    if probability < 0.33:
        return "🟢"
    elif probability < 0.66:
        return "🟡"
    else:
        return "🔴"

def format_percentage(value):
    """Format decimal as percentage"""
    return f"{value:.1%}"

def format_decimal(value, decimals=2):
    """Format decimal with specified decimal places"""
    return f"{value:.{decimals}f}"

def get_age_group(age):
    """Get age group based on age"""
    if age < 40:
        return 1, "< 40 years"
    elif age < 50:
        return 2, "40-49 years"
    elif age < 60:
        return 3, "50-59 years"
    else:
        return 4, "60+ years"

def count_risk_factors(current_smoker, diabetes, prevalent_stroke, prevalent_hyp):
    """Count total risk factors"""
    return current_smoker + diabetes + prevalent_stroke + prevalent_hyp

def get_recommendations_by_risk_level(user_data, risk_probability):
    """Generate recommendations based on risk level and user profile"""
    recommendations = []
    
    # SMOKING - HIGHEST PRIORITY
    if user_data.get('currentSmoker') == 1:
        recommendations.append({
            'priority': 'HIGHEST',
            'emoji': '🔴',
            'title': 'Quit Smoking',
            'description': 'Smoking is the top modifiable risk factor. Quitting reduces risk by 50% within 1 year.',
            'action': 'Start nicotine replacement therapy or consult a smoking cessation program.'
        })
    
    # BLOOD PRESSURE MANAGEMENT - HIGH PRIORITY
    if user_data.get('sysBP', 0) > 140 or user_data.get('diaBP', 0) > 90:
        recommendations.append({
            'priority': 'HIGH',
            'emoji': '🟠',
            'title': 'Manage Blood Pressure',
            'description': 'Your BP is elevated. Control through diet, exercise, and medication if needed.',
            'action': 'Reduce salt intake, exercise 30 mins daily, monitor BP regularly.'
        })
    
    # CHOLESTEROL - HIGH PRIORITY
    if user_data.get('totChol', 0) > 240:
        recommendations.append({
            'priority': 'HIGH',
            'emoji': '🟠',
            'title': 'Lower Cholesterol',
            'description': 'High cholesterol increases heart disease risk significantly.',
            'action': 'Eat heart-healthy foods (fish, nuts, whole grains), reduce saturated fats.'
        })
    
    # WEIGHT MANAGEMENT - HIGH PRIORITY
    if user_data.get('BMI', 0) > 30:
        recommendations.append({
            'priority': 'HIGH',
            'emoji': '🟠',
            'title': 'Weight Management',
            'description': 'Weight loss can significantly reduce your risk.',
            'action': 'Aim for 5-10% weight loss through diet and exercise.'
        })
    
    # DIABETES MANAGEMENT - HIGH PRIORITY
    if user_data.get('diabetes') == 1:
        recommendations.append({
            'priority': 'HIGH',
            'emoji': '🟠',
            'title': 'Manage Diabetes',
            'description': 'Diabetics have 2-4x higher heart disease risk.',
            'action': 'Monitor blood glucose, take medications as prescribed, eat balanced meals.'
        })
    
    # BLOOD SUGAR CONTROL - MEDIUM PRIORITY
    if user_data.get('glucose', 0) > 125:
        recommendations.append({
            'priority': 'MEDIUM',
            'emoji': '🟡',
            'title': 'Control Blood Sugar',
            'description': 'Pre-diabetic glucose levels need attention.',
            'action': 'Reduce refined sugars, increase fiber, maintain healthy weight.'
        })
    
    # GENERAL RECOMMENDATIONS - MEDIUM/LOW PRIORITY
    recommendations.append({
        'priority': 'MEDIUM',
        'emoji': '🟡',
        'title': 'Exercise Regularly',
        'description': 'Physical activity strengthens your heart.',
        'action': '150 minutes of moderate aerobic exercise per week is recommended.'
    })
    
    recommendations.append({
        'priority': 'MEDIUM',
        'emoji': '🟡',
        'title': 'Healthy Diet',
        'description': 'Nutrition is key to heart health.',
        'action': 'Follow Mediterranean or DASH diet, reduce processed foods.'
    })
    
    recommendations.append({
        'priority': 'LOW',
        'emoji': '🟢',
        'title': 'Stress Management',
        'description': 'Chronic stress increases heart disease risk.',
        'action': 'Practice meditation, yoga, or deep breathing exercises.'
    })
    
    recommendations.append({
        'priority': 'LOW',
        'emoji': '🟢',
        'title': 'Regular Checkups',
        'description': 'Monitor your health consistently.',
        'action': 'Schedule annual heart health screening with your doctor.'
    })
    
    return recommendations

def get_summary_text(prediction, probability):
    """Generate summary text based on prediction"""
    if prediction == 1:
        return f"⚠️ **HIGH RISK**: You have a {probability[1]:.1%} probability of developing heart disease in the next 10 years."
    else:
        return f"✅ **LOW RISK**: You have a {probability[1]:.1%} probability of developing heart disease in the next 10 years."

def validate_user_input(user_data):
    """Validate user input data"""
    errors = []
    
    if user_data.get('age', 0) < 0 or user_data.get('age', 0) > 120:
        errors.append("Age must be between 0 and 120")
    
    if user_data.get('sysBP', 0) < 50 or user_data.get('sysBP', 0) > 300:
        errors.append("Systolic BP must be between 50 and 300")
    
    if user_data.get('totChol', 0) < 50 or user_data.get('totChol', 0) > 600:
        errors.append("Cholesterol must be between 50 and 600")
    
    return errors