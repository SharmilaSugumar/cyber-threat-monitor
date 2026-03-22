import re
import json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score
import numpy as np

from .training_data import get_training_data


# ── Rule definitions ──────────────────────────────────────────────────────────
RULES = [
    {"name": "brute_force",          "pattern": r"failed.{0,20}(login|password|auth)",    "weight": 0.45},
    {"name": "account_lockout",      "pattern": r"account.{0,15}(locked|disabled|blocked)", "weight": 0.35},
    {"name": "port_scan",            "pattern": r"port.{0,10}scan",                        "weight": 0.50},
    {"name": "unauthorized_access",  "pattern": r"unauthori[sz]ed.{0,20}(access|attempt)", "weight": 0.55},
    {"name": "privilege_escalation", "pattern": r"privilege.{0,15}escalat",                "weight": 0.65},
    {"name": "malware",              "pattern": r"(malware|ransomware|trojan|rootkit|virus)", "weight": 0.80},
    {"name": "data_exfiltration",    "pattern": r"(exfil|data.{0,10}leak|large.{0,15}transfer)", "weight": 0.70},
    {"name": "c2_beacon",            "pattern": r"(c2|command.{0,10}control|beacon|cobalt)", "weight": 0.75},
    {"name": "sql_injection",        "pattern": r"(sql.{0,10}inject|union.{0,10}select|xss|csrf)", "weight": 0.60},
    {"name": "ddos",                 "pattern": r"(ddos|flood|syn.{0,10}flood|amplification)", "weight": 0.60},
    {"name": "lateral_movement",     "pattern": r"lateral.{0,15}movement",                 "weight": 0.65},
    {"name": "persistence",          "pattern": r"(persistence|scheduled.{0,10}task|registry.{0,10}run)", "weight": 0.55},
    {"name": "credential_dump",      "pattern": r"(mimikatz|credential.{0,10}dump|pass.{0,10}hash)", "weight": 0.80},
    {"name": "powershell_abuse",     "pattern": r"(encoded.{0,15}powershell|obfuscat|base64.{0,10}decode)", "weight": 0.60},
    {"name": "cloud_attack",         "pattern": r"(s3.{0,15}public|iam.{0,10}permissive|cloudtrail.{0,10}disabled)", "weight": 0.65},
]


class RuleEngine:
    def check(self, text: str) -> dict:
        text_lower = text.lower()
        triggered = []
        score = 0.0
        for rule in RULES:
            if re.search(rule["pattern"], text_lower, re.IGNORECASE):
                triggered.append({"rule": rule["name"], "description": rule["name"].replace("_", " ").title()})
                score += rule["weight"]
        return {
            "triggered_rules": triggered,
            "rule_score": min(score, 1.0),
            "is_suspicious": len(triggered) > 0,
        }


class SVMDetector:
    def __init__(self):
        svm = Pipeline([
            ("tfidf", TfidfVectorizer(max_features=3000, ngram_range=(1, 3), sublinear_tf=True)),
            ("clf",   SVC(kernel="rbf", probability=True, C=10, gamma="scale")),
        ])
        rf = Pipeline([
            ("tfidf", TfidfVectorizer(max_features=3000, ngram_range=(1, 2), sublinear_tf=True)),
            ("clf",   RandomForestClassifier(n_estimators=200, random_state=42)),
        ])
        self.model = VotingClassifier(
            estimators=[("svm", svm), ("rf", rf)],
            voting="soft",
        )
        self.is_trained = False

    def train(self, texts, labels):
        self.model.fit(texts, labels)
        self.is_trained = True
        scores = cross_val_score(self.model, texts, labels, cv=5, scoring="f1")
        print(f"✅ Ensemble trained — CV F1: {scores.mean():.3f} ± {scores.std():.3f}")

    def predict(self, text: str) -> dict:
        if not self.is_trained:
            return {"label": "unknown", "confidence": 0.0, "anomaly_score": 0.0}
        proba = self.model.predict_proba([text])[0]
        label = "anomaly" if proba[1] > 0.5 else "normal"
        return {
            "label": label,
            "confidence": float(max(proba)),
            "anomaly_score": float(proba[1]),
        }


class SeverityScorer:
    def calculate(self, ml_score: float, rule_score: float, entity_count: int) -> dict:
        entity_score = min(entity_count * 0.08, 1.0)
        final = 0.50 * ml_score + 0.30 * rule_score + 0.20 * entity_score
        level = "HIGH" if final >= 0.68 else "MEDIUM" if final >= 0.38 else "LOW"
        return {"score": round(final, 3), "level": level}


class HybridDetectionEngine:
    def __init__(self):
        self.svm   = SVMDetector()
        self.rules = RuleEngine()
        self.scorer = SeverityScorer()
        self._train()

    def _train(self):
        texts, labels = get_training_data()
        self.svm.train(texts, labels)

    def extract_entities(self, text: str) -> dict:
        ips   = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))
        users = list(set(re.findall(r"user\s+(\w+)", text, re.IGNORECASE)))
        ports = list(set(re.findall(r"port\s+(\d+)", text, re.IGNORECASE)))
        return {"ips": ips, "users": users, "ports": ports, "count": len(ips) + len(users)}

    def analyze(self, text: str) -> dict:
        ml     = self.svm.predict(text)
        rules  = self.rules.check(text)
        ents   = self.extract_entities(text)
        sev    = self.scorer.calculate(ml["anomaly_score"], rules["rule_score"], ents["count"])
        is_anom = ml["label"] == "anomaly" or rules["is_suspicious"]

        reasons = []
        if ml["label"] == "anomaly":
            reasons.append(f"AI model detected anomaly (confidence: {ml['confidence']:.0%})")
        for r in rules["triggered_rules"]:
            reasons.append(r["description"] + " detected")
        if ents["ips"]:
            reasons.append(f"Suspicious IPs: {', '.join(ents['ips'])}")
        if ents["users"]:
            reasons.append(f"Targeted users: {', '.join(ents['users'])}")

        return {
            "is_anomaly":    is_anom,
            "ml_prediction": ml,
            "rule_analysis": rules,
            "entities":      ents,
            "severity":      sev,
            "explanation":   reasons,
        }