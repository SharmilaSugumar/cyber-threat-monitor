from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
import torch

class TransformerDetector:
    
    def __init__(self):
        print("Loading DistilBERT... (first time takes 1-2 minutes)")
        self.tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
        self.model = DistilBertForSequenceClassification.from_pretrained(
            'distilbert-base-uncased',
            num_labels=2  # 0=normal, 1=anomaly
        )
        self.model.eval()
        print("DistilBERT loaded!")
    
    def predict(self, text: str) -> dict:
        """
        How it works:
        1. Tokenize: split text into subword pieces
        2. Attention: each word attends to every other word
        3. Classification: normal vs anomaly
        """
        # Step 1: tokenize (max 512 tokens)
        inputs = self.tokenizer(
            text,
            return_tensors='pt',
            max_length=512,
            truncation=True,
            padding=True
        )
        
        # Step 2: forward pass (no gradient needed for inference)
        with torch.no_grad():
            outputs = self.model(**inputs)
        
        # Step 3: convert logits to probabilities
        probs = torch.softmax(outputs.logits, dim=1)[0]
        
        label = 'anomaly' if probs[1] > 0.5 else 'normal'
        
        return {
            'label': label,
            'confidence': float(probs.max()),
            'anomaly_score': float(probs[1]),
            'normal_score': float(probs[0])
        }