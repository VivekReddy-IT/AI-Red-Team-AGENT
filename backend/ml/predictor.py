import os
import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
import joblib

ML_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(ML_DIR, "dataset.json")
MODEL_PATH = os.path.join(ML_DIR, "payload_model.pkl")

class SmartPredictor:
    def __init__(self):
        self.model = None

    def initialize_model(self):
        """Loads the model or trains it on startup if not present."""
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
        else:
            self._train_and_save()

    def _train_and_save(self):
        if not os.path.exists(DATASET_PATH):
            raise FileNotFoundError("Missing dataset.json to train the ML model.")
            
        with open(DATASET_PATH, 'r') as f:
            data = json.load(f)
            
        # In a real scenario, this dataset would be massive, gathered from CVEs.
        X = [item["input_name"].lower() for item in data]
        y = [item["likely_vuln"] for item in data]
        
        # We use a simple NLP TF-IDF pipeline paired with Naive Bayes for fast probabilistic classification
        self.model = make_pipeline(
            TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 4)), 
            MultinomialNB()
        )
        self.model.fit(X, y)
        
        joblib.dump(self.model, MODEL_PATH)

    def predict_optimal_payload_type(self, input_name: str) -> dict:
        """
        Returns the most probable vulnerability class for an input field 
        and its confidence score.
        """
        if not self.model:
            self.initialize_model()
            
        # Predict probability for all classes
        probs = self.model.predict_proba([input_name.lower()])[0]
        max_prob_index = np.argmax(probs)
        
        confidence = float(probs[max_prob_index])
        predicted_class = self.model.classes_[max_prob_index]
        
        return {
            "predicted_type": predicted_class,
            "confidence_score": round(confidence * 100, 2)
        }

# Global singleton instance
predictor = SmartPredictor()
