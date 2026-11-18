from heart_disease_predictor import HeartDiseasePredictor

def main():
    print("="*60)
    print("GUARDIAN HEART - KNN MODEL TRAINING")
    print("="*60)
    
    # Initialize predictor
    predictor = HeartDiseasePredictor()
    
    # Load data
    try:
        df = predictor.load_data('framingham.csv')
    except FileNotFoundError:
        print("❌ Error: framingham.csv not found!")
        print("Please ensure the Framingham dataset is in the current directory.")
        return
    
    # Preprocess
    df = predictor.preprocess_data(df)
    
    # Feature engineering
    df = predictor.engineer_features(df)
    
    # Prepare features
    X, y, features = predictor.prepare_features(df, target_column='TenYearCHD')
    
    # Split data
    predictor.split_data(X, y)
    
    # Scale features
    predictor.scale_features()
    
    # Train KNN model
    predictor.train_knn(n_neighbors=7, metric='euclidean', weights='uniform')
    
    # Evaluate
    predictor.evaluate_model()
    
    # Save model
    predictor.save_model('heart_disease_model.pkl')
    
    print("\n" + "="*60)
    print("✓ MODEL TRAINING COMPLETE!")
    print("="*60)

if __name__ == "__main__":
    main()