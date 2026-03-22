import re

RULES = [
    {
        'name': 'brute_force',
        'pattern': r'failed.*(login|password)',
        'weight': 0.4,
        'description': 'Repeated failed login attempts'
    },
    {
        'name': 'port_scan',
        'pattern': r'port.?scan',
        'weight': 0.5,
        'description': 'Port scanning activity detected'
    },
    {
        'name': 'unauthorized_access',
        'pattern': r'unauthorized.*(access|attempt)',
        'weight': 0.6,
        'description': 'Unauthorized access attempt'
    },
    {
        'name': 'account_locked',
        'pattern': r'account.*(locked|blocked)',
        'weight': 0.3,
        'description': 'Account lockout triggered'
    },
    {
        'name': 'privilege_escalation',
        'pattern': r'privilege.*(escalat|escalation)',
        'weight': 0.7,
        'description': 'Possible privilege escalation'
    },
]

class RuleEngine:
    
    def check(self, text: str) -> dict:
        triggered = []
        rule_score = 0.0
        
        for rule in RULES:
            if re.search(rule['pattern'], text, re.IGNORECASE):
                triggered.append({
                    'rule': rule['name'],
                    'description': rule['description']
                })
                rule_score += rule['weight']
        
        # Cap at 1.0
        rule_score = min(rule_score, 1.0)
        
        return {
            'triggered_rules': triggered,
            'rule_score': rule_score,
            'is_suspicious': len(triggered) > 0
        }


class SeverityScorer:
    
    def calculate(self, ml_score: float, rule_score: float, entity_count: int) -> dict:
        """
        Formula: Severity = α(ML) + β(rules) + γ(entities)
        α=0.5, β=0.3, γ=0.2
        """
        alpha = 0.5
        beta = 0.3
        gamma = 0.2
        
        entity_score = min(entity_count * 0.1, 1.0)
        
        final_score = (alpha * ml_score) + (beta * rule_score) + (gamma * entity_score)
        
        if final_score >= 0.7:
            level = 'HIGH'
        elif final_score >= 0.4:
            level = 'MEDIUM'
        else:
            level = 'LOW'
        
        return {
            'score': round(final_score, 3),
            'level': level
        }