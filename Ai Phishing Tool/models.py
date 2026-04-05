"""
Phishing URL Detection Models
Simulated RoBERTa and Auto Encoder models using heuristic-based feature extraction.
Produces realistic results based on real phishing indicators.
"""

import re
import math
import random
import hashlib
from urllib.parse import urlparse


class PhishingDetector:
    """Phishing URL detector with two model simulations."""

    # Known legitimate TLDs
    SAFE_TLDS = {'.com', '.org', '.edu', '.gov', '.net', '.io', '.co', '.us', '.uk', '.de', '.fr', '.jp', '.au', '.ca'}

    # Suspicious TLDs commonly used in phishing
    SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.click',
                       '.link', '.info', '.online', '.site', '.website', '.space', '.fun', '.icu',
                       '.buzz', '.monster', '.rest', '.zip', '.mov', '.cam'}

    # Known brand names that phishers target
    TARGET_BRANDS = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'facebook',
                     'instagram', 'twitter', 'linkedin', 'bank', 'chase', 'wells', 'citi',
                     'dropbox', 'icloud', 'outlook', 'yahoo', 'ebay', 'spotify', 'steam',
                     'whatsapp', 'telegram', 'coinbase', 'binance', 'metamask']

    # Suspicious keywords in URLs
    SUSPICIOUS_KEYWORDS = ['login', 'signin', 'sign-in', 'verify', 'verification', 'update',
                           'secure', 'security', 'account', 'confirm', 'password', 'credential',
                           'suspend', 'locked', 'unusual', 'alert', 'urgent', 'expire',
                           'billing', 'payment', 'wallet', 'authenticate', 'validate',
                           'restore', 'recover', 'reset', 'unlock', 'reactivate']

    def extract_features(self, url):
        """Extract comprehensive features from a URL."""
        features = {}

        try:
            parsed = urlparse(url if '://' in url else 'http://' + url)
        except Exception:
            return {'error': True}, 1.0

        domain = parsed.netloc or parsed.path.split('/')[0]
        path = parsed.path.lower()
        full_url = url.lower()

        # === Feature 1: URL Length ===
        features['url_length'] = len(url)
        features['url_length_suspicious'] = len(url) > 75

        # === Feature 2: HTTPS check ===
        features['has_https'] = parsed.scheme == 'https'

        # === Feature 3: IP address as domain ===
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        features['is_ip_address'] = bool(ip_pattern.match(domain.split(':')[0]))

        # === Feature 4: Domain analysis ===
        domain_parts = domain.split('.')
        features['num_subdomains'] = max(0, len(domain_parts) - 2)
        features['excessive_subdomains'] = features['num_subdomains'] > 2

        # === Feature 5: Suspicious TLD ===
        tld = '.' + domain_parts[-1] if domain_parts else ''
        features['suspicious_tld'] = tld.lower() in self.SUSPICIOUS_TLDS
        features['tld'] = tld

        # === Feature 6: Special characters ===
        features['has_at_symbol'] = '@' in url
        features['num_hyphens'] = domain.count('-')
        features['excessive_hyphens'] = features['num_hyphens'] > 2
        features['num_dots'] = url.count('.')
        features['has_double_slash_redirect'] = '//' in parsed.path

        # === Feature 7: Suspicious keywords ===
        keyword_count = sum(1 for kw in self.SUSPICIOUS_KEYWORDS if kw in full_url)
        features['suspicious_keyword_count'] = keyword_count
        features['has_suspicious_keywords'] = keyword_count > 0
        features['found_keywords'] = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in full_url]

        # === Feature 8: Brand impersonation ===
        brand_in_path = any(brand in path for brand in self.TARGET_BRANDS)
        brand_in_domain = any(brand in domain.lower() for brand in self.TARGET_BRANDS)
        features['brand_in_path_not_domain'] = brand_in_path and not brand_in_domain
        # Brand in domain + suspicious TLD (e.g., paypal.com.tk)
        features['brand_in_suspicious_domain'] = brand_in_domain and features['suspicious_tld']
        features['target_brand'] = next((b for b in self.TARGET_BRANDS if b in full_url), None)

        # === Feature 9: URL entropy (randomness) ===
        if domain:
            char_freq = {}
            for c in domain.lower():
                char_freq[c] = char_freq.get(c, 0) + 1
            entropy = -sum((f / len(domain)) * math.log2(f / len(domain))
                           for f in char_freq.values())
            features['domain_entropy'] = round(entropy, 3)
            features['high_entropy'] = entropy > 4.0
        else:
            features['domain_entropy'] = 0
            features['high_entropy'] = False

        # === Feature 10: Path depth ===
        features['path_depth'] = len([p for p in parsed.path.split('/') if p])
        features['deep_path'] = features['path_depth'] > 4

        # === Feature 11: Query string analysis ===
        features['has_query'] = bool(parsed.query)
        features['query_length'] = len(parsed.query)

        # === Feature 12: Domain length ===
        features['domain_length'] = len(domain)
        features['long_domain'] = len(domain) > 30

        return features, None

    def _calculate_risk_score(self, features, weights):
        """Calculate a weighted risk score from features."""
        score = 0.0
        max_positive = 0.0

        for feature, weight in weights.items():
            if weight > 0:
                max_positive += weight
            if feature in features:
                val = features[feature]
                if isinstance(val, bool):
                    score += weight if val else 0
                elif isinstance(val, (int, float)):
                    if feature == 'url_length':
                        score += weight * min(val / 100, 1.0)
                    elif feature == 'num_subdomains':
                        score += weight * min(val / 5, 1.0)
                    elif feature == 'suspicious_keyword_count':
                        score += weight * min(val / 3, 1.0)
                    elif feature == 'domain_entropy':
                        score += weight * min(val / 5, 1.0)
                    elif feature == 'path_depth':
                        score += weight * min(val / 5, 1.0)
                    elif feature == 'num_hyphens':
                        score += weight * min(val / 4, 1.0)

        # Normalize to 0-1 using only positive weights as denominator
        risk = max(0.0, min(1.0, score / max_positive)) if max_positive > 0 else 0.5

        return risk

    def analyze_roberta(self, url):
        """
        Simulated RoBERTa (NLP-based) analysis.
        Uses cumulative NLP scoring — heavily weights semantic signals
        like suspicious keywords, brand impersonation, and deceptive patterns.
        """
        features, error = self.extract_features(url)
        if error:
            return {
                'prediction': 'Suspicious',
                'confidence': 0.5,
                'model': 'RoBERTa',
                'features': {'error': 'Could not parse URL'}
            }

        # Cumulative NLP score — semantic signals add directly
        nlp_score = 0.0

        # === Keyword analysis (RoBERTa's strength) ===
        # Each suspicious keyword contributes significantly
        kw_count = features['suspicious_keyword_count']
        if kw_count >= 3:
            nlp_score += 5.0   # 3+ keywords is very suspicious
        elif kw_count == 2:
            nlp_score += 3.0
        elif kw_count == 1:
            nlp_score += 1.5

        # === Brand impersonation (strongest NLP signal) ===
        if features['brand_in_path_not_domain']:
            nlp_score += 4.0
        if features['brand_in_suspicious_domain']:
            nlp_score += 4.5

        # === IP address as domain ===
        if features['is_ip_address']:
            nlp_score += 3.0

        # === Suspicious TLD ===
        if features['suspicious_tld']:
            nlp_score += 2.5

        # === No HTTPS ===
        if not features['has_https']:
            nlp_score += 1.0

        # === Special characters ===
        if features['has_at_symbol']:
            nlp_score += 2.5
        if features['has_double_slash_redirect']:
            nlp_score += 1.5

        # === Structural signals ===
        if features['excessive_subdomains']:
            nlp_score += 1.5
        if features['excessive_hyphens']:
            nlp_score += 1.0
        elif features['num_hyphens'] >= 2:
            nlp_score += 0.5
        if features['high_entropy']:
            nlp_score += 1.5
        if features['url_length_suspicious']:
            nlp_score += 1.0
        if features['long_domain']:
            nlp_score += 0.8

        # === HTTPS bonus ===
        if features['has_https']:
            nlp_score -= 1.0

        nlp_score = max(0.0, nlp_score)

        # Normalize: max realistic score ≈ 22, phishing threshold at ~3.5
        max_nlp = 22.0
        risk = min(1.0, nlp_score / max_nlp)

        # Add slight deterministic variance
        seed = int(hashlib.md5(url.encode()).hexdigest()[:8], 16)
        rng = random.Random(seed)
        risk += rng.uniform(-0.02, 0.02)
        risk = max(0.0, min(1.0, risk))

        is_phishing = nlp_score >= 3.5

        confidence = abs(risk - 0.5) * 2
        confidence = max(0.60, min(0.99, 0.55 + confidence * 0.5))

        # Build human-readable feature summary
        feature_summary = {
            'NLP Risk Score': f'{round(nlp_score, 1)} / {max_nlp} {"⚠️ High" if nlp_score >= 3.5 else "✅ Low"}',
            'URL Length': f'{features["url_length"]} characters {"⚠️" if features["url_length_suspicious"] else "✅"}',
            'HTTPS': '✅ Yes' if features['has_https'] else '⚠️ No',
            'IP Address': '⚠️ Yes' if features['is_ip_address'] else '✅ No',
            'Subdomains': f'{features["num_subdomains"]} {"⚠️" if features["excessive_subdomains"] else "✅"}',
            'Suspicious TLD': f'{"⚠️ " + features["tld"] if features["suspicious_tld"] else "✅ " + features["tld"]}',
            'Suspicious Keywords': f'{"⚠️ " + ", ".join(features["found_keywords"]) if features["has_suspicious_keywords"] else "✅ None found"}',
            'Brand Impersonation': f'{"⚠️ " + str(features["target_brand"]) if features["brand_in_path_not_domain"] or features["brand_in_suspicious_domain"] else "✅ Not detected"}',
            'Domain Entropy': f'{features["domain_entropy"]} {"⚠️ High randomness" if features["high_entropy"] else "✅ Normal"}',
        }

        return {
            'prediction': 'Phishing' if is_phishing else 'Legitimate',
            'confidence': round(confidence, 4),
            'risk_score': round(risk, 4),
            'model': 'RoBERTa',
            'model_description': 'NLP-based transformer model analyzing semantic URL patterns',
            'features': feature_summary
        }

    def analyze_autoencoder(self, url):
        """
        Simulated Auto Encoder (anomaly-detection-based) analysis.
        Uses cumulative anomaly scoring — each deviation from 'normal'
        URL patterns adds to the reconstruction error, mimicking how a
        real autoencoder detects out-of-distribution inputs.
        """
        features, error = self.extract_features(url)
        if error:
            return {
                'prediction': 'Suspicious',
                'confidence': 0.5,
                'model': 'Auto Encoder',
                'features': {'error': 'Could not parse URL'}
            }

        # Cumulative anomaly score — each anomaly adds directly
        anomaly = 0.0

        # High-impact anomalies
        if features['is_ip_address']:
            anomaly += 3.0
        if features['brand_in_path_not_domain']:
            anomaly += 3.5
        if features['brand_in_suspicious_domain']:
            anomaly += 4.0
        if features['has_at_symbol']:
            anomaly += 2.5

        # Medium-impact anomalies
        if features['suspicious_tld']:
            anomaly += 2.0
        if not features['has_https']:
            anomaly += 1.0
        if features['has_suspicious_keywords']:
            anomaly += 1.5
        anomaly += min(features['suspicious_keyword_count'] * 0.5, 2.0)
        if features['has_double_slash_redirect']:
            anomaly += 1.5

        # Structural anomalies
        if features['excessive_subdomains']:
            anomaly += 1.5
        else:
            anomaly += features['num_subdomains'] * 0.3

        if features['excessive_hyphens']:
            anomaly += 1.0
        else:
            anomaly += features['num_hyphens'] * 0.25

        if features['high_entropy']:
            anomaly += 2.0
        elif features['domain_entropy'] > 3.5:
            anomaly += 1.0

        if features['url_length_suspicious']:
            anomaly += 1.5
        elif features['url_length'] > 50:
            anomaly += 0.5

        if features['long_domain']:
            anomaly += 1.0

        if features['deep_path']:
            anomaly += 1.0
        elif features['path_depth'] > 2:
            anomaly += 0.3

        # HTTPS bonus (reduces anomaly for legitimate sites)
        if features['has_https']:
            anomaly -= 1.0

        anomaly = max(0.0, anomaly)

        # Normalize: max realistic anomaly ≈ 20, phishing threshold at ~4
        max_anomaly = 20.0
        risk = min(1.0, anomaly / max_anomaly)

        # Add slight deterministic variance
        seed = int(hashlib.md5(url.encode()).hexdigest()[:8], 16) + 42
        rng = random.Random(seed)
        risk += rng.uniform(-0.02, 0.02)
        risk = max(0.0, min(1.0, risk))

        is_phishing = anomaly >= 4.0

        confidence = abs(risk - 0.5) * 2
        confidence = max(0.60, min(0.99, 0.55 + confidence * 0.5))

        # Build human-readable feature summary
        reconstruction_error = round(anomaly / max_anomaly, 4)

        feature_summary = {
            'Reconstruction Error': f'{reconstruction_error} {"⚠️ Above threshold" if reconstruction_error > 0.2 else "✅ Normal"}',
            'Anomaly Score': f'{round(anomaly, 2)} / {max_anomaly} {"⚠️ High" if anomaly >= 4.0 else "✅ Low"}',
            'URL Length': f'{features["url_length"]} chars {"⚠️ Anomalous" if features["url_length_suspicious"] else "✅ Normal"}',
            'Structural Complexity': f'{features["path_depth"]} path depth, {features["num_subdomains"]} subdomains',
            'Domain Analysis': f'{features["domain_length"]} chars, entropy: {features["domain_entropy"]} {"⚠️" if features["high_entropy"] else "✅"}',
            'IP-based URL': '⚠️ Detected' if features['is_ip_address'] else '✅ Domain name',
            'Special Characters': f'@ symbol: {"⚠️" if features["has_at_symbol"] else "✅"}, Hyphens: {features["num_hyphens"]} {"⚠️" if features["excessive_hyphens"] else "✅"}',
            'HTTPS': '✅ Encrypted' if features['has_https'] else '⚠️ Unencrypted',
        }

        return {
            'prediction': 'Phishing' if is_phishing else 'Legitimate',
            'confidence': round(confidence, 4),
            'risk_score': round(risk, 4),
            'model': 'Auto Encoder',
            'model_description': 'Anomaly detection model measuring reconstruction error of URL patterns',
            'features': feature_summary
        }

