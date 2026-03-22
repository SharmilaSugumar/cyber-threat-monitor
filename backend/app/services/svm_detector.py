from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC
from sklearn.pipeline import Pipeline
import pickle

class SVMDetector:
    
    def __init__(self):
        # Pipeline: TF-IDF → SVM
        self.model = Pipeline([
            ('tfidf', TfidfVectorizer(max_features=500, ngram_range=(1,2))),
            ('svm', SVC(kernel='rbf', probability=True))
        ])
        self.is_trained = False
    
    def train(self, texts: list, labels: list):
        """
        texts: list of log sequence strings
        labels: list of 0 (normal) or 1 (anomaly)
        """
        self.model.fit(texts, labels)
        self.is_trained = True
        print("SVM trained successfully")
    
    def predict(self, text: str) -> dict:
        if not self.is_trained:
            return {'label': 'unknown', 'confidence': 0.0}
        
        proba = self.model.predict_proba([text])[0]
        label = 'anomaly' if proba[1] > 0.5 else 'normal'
        
        return {
            'label': label,
            'confidence': float(max(proba)),
            'anomaly_score': float(proba[1])
        }
    
    def save(self, path: str):
        with open(path, 'wb') as f:
            pickle.dump(self.model, f)
    
    def load(self, path: str):
        with open(path, 'rb') as f:
            self.model = pickle.load(f)
        self.is_trained = True