"""
Production-grade password strength analyzer with zxcvbn-inspired pattern detection.
Uses Flask to provide a REST API for the frontend.

Reference: NIST SP 800-63B Revision 4 + Dropbox zxcvbn (Wheeler, 2016)
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import math
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Common passwords (top 5000 for production - using subset here)
COMMON_PASSWORDS = {
    'password', 'password123', '12345678', 'qwerty', '123456', 'abc123', 'letmein',
    'monkey', '1q2w3e4r', '123123', 'password1', 'welcome', 'login', 'admin',
    'passw0rd', '1234567', 'dragon', '123321', 'mustang', '666666', 'master',
    'batman', '123456789', 'iloveyou', 'princess', 'michael', 'sunshine', 'ashley',
    'bailey', 'passpass', 'shadow', '123654', 'superman', 'qazwsx',
    'football', 'baseball', 'trustno1', 'starwars', 'thomas', 'jordan',
    'daniel', 'jessica', 'jennifer', 'william', 'christopher', 'samurai',
    'samsung', 'opensesame', 'hunter', 'killer', 'toor', 'root',
    'admin123', 'password@', 'pass', 'pass123', 'test', 'test123',
    'welcome123', 'hello', 'hello123', 'qwerty123', 'guest', 'guest123',
    'root123', 'admin@123', 'password@123', 'letmein123', 'monkey123',
    'superman123', 'batman123', 'starwars123', 'princess123', '111111'
}

# Dictionary for common words (production: 100k+)
COMMON_WORDS = {
    'password', 'admin', 'login', 'welcome', 'letmein', 'master', 'dragon',
    'admin', 'user', 'account', 'root', 'system', 'server', 'database',
    'secret', 'private', 'access', 'grant', 'allow', 'deny', 'block',
    'email', 'phone', 'address', 'person', 'people', 'hello', 'world'
}

# Keyboard patterns
KEYBOARD_PATTERNS = {
    'qwerty': ['qwerty', 'ytrewq', 'qwertyuiop', 'poiuytrewq'],
    'asdf': ['asdf', 'fdsa', 'asdfghjkl', 'lkjhgfdsa'],
    'numpad': ['12345', '54321', '123456', '654321', '1234567890', '0987654321'],
    'zxcv': ['zxcvbnm', 'mnbvcxz'],
}

QWERTY_KEYBOARD = """
qwertyuiopasdfghjklzxcvbnm
123456789012345678901234567890
"""

# Common name patterns
COMMON_NAMES = {
    'john', 'jane', 'michael', 'christopher', 'jennifer', 'jessica',
    'david', 'james', 'robert', 'william', 'daniel', 'matthew',
    'anthony', 'mark', 'donald', 'thomas', 'charles', 'george',
    'mary', 'sandra', 'ashley', 'kimberly', 'emily', 'donna',
    'michelle', 'dorothy', 'carol', 'barbara', 'margaret', 'susan'
}


class PasswordAnalyzer:
    """
    Analyzes password strength using multiple heuristics.
    Returns actionable metrics based on security research.
    """

    def __init__(self, password):
        self.password = password
        self.length = len(password)
        self.patterns = []
        self.guesses = self.estimate_guesses()

    def estimate_guesses(self):
        """
        Estimate guesses needed to crack password.
        Uses combination of entropy and pattern detection.
        """
        if self.password in COMMON_PASSWORDS:
            return 10  # Already in breach databases

        # Shannon entropy baseline
        entropy_score = self.calculate_entropy()
        entropy_guesses = 2 ** entropy_score

        # Pattern-based penalties
        penalty_factor = 1.0

        if self.detect_common_word():
            penalty_factor *= 0.01  # Dictionary attack speeds it up
            self.patterns.append('common_word')

        if self.detect_keyboard_pattern():
            penalty_factor *= 0.05
            self.patterns.append('keyboard')

        if self.detect_date_pattern():
            penalty_factor *= 0.02
            self.patterns.append('date')

        if self.detect_l33t():
            penalty_factor *= 0.1
            self.patterns.append('l33t')

        if self.detect_repeats():
            penalty_factor *= 0.3
            self.patterns.append('repeats')

        if self.detect_sequences():
            penalty_factor *= 0.2
            self.patterns.append('sequences')

        return max(entropy_guesses * penalty_factor, 10)

    def calculate_entropy(self):
        """Shannon entropy: H = L * log2(C)"""
        pool_size = 0
        if re.search(r'[a-z]', self.password):
            pool_size += 26
        if re.search(r'[A-Z]', self.password):
            pool_size += 26
        if re.search(r'[0-9]', self.password):
            pool_size += 10
        if re.search(r'[^a-zA-Z0-9]', self.password):
            pool_size += 32

        if pool_size == 0:
            return 0

        return self.length * math.log2(pool_size)

    def detect_common_word(self):
        """Check if password contains common dictionary words."""
        pwd_lower = self.password.lower()
        for word in COMMON_WORDS:
            if word in pwd_lower and len(word) >= 4:
                return True
        for name in COMMON_NAMES:
            if name in pwd_lower:
                return True
        return False

    def detect_keyboard_pattern(self):
        """Detect keyboard walks: qwerty, asdf, numpad sequences."""
        pwd_lower = self.password.lower()
        for pattern_group in KEYBOARD_PATTERNS.values():
            for pattern in pattern_group:
                if pattern in pwd_lower:
                    return True
        # Check for adjacent keys (simplified)
        for i in range(len(pwd_lower) - 2):
            substr = pwd_lower[i:i+3]
            if substr in 'qwerty' or substr in 'asdf' or substr in 'zxcv':
                if all(c in 'qwertyasdfzxcv' for c in substr):
                    return True
        return False

    def detect_date_pattern(self):
        """Detect common date patterns: DDMMYYYY, MM/YYYY, YYYY, etc."""
        # Years
        if re.search(r'(19|20)\d{2}', self.password):
            return True
        # MM/DD or DD/MM
        if re.search(r'\d{1,2}[/-]\d{1,2}', self.password):
            return True
        # Common date numbers
        if re.search(r'(01|12|11|10|09|08|07|06|05|04|03|02)', self.password):
            if re.search(r'\d{2}', self.password):
                return True
        return False

    def detect_l33t(self):
        """Detect leetspeak substitutions."""
        l33t_map = {'0': 'o', '@': 'a', '1': 'i', '3': 'e', '5': 's', '7': 't', '4': 'a'}
        original = self.password.lower()
        for char, replacement in l33t_map.items():
            if char in original:
                decoded = original.replace(char, replacement)
                if decoded in COMMON_WORDS or any(w in decoded for w in COMMON_WORDS):
                    return True
        return False

    def detect_repeats(self):
        """Detect repeating characters: aaa, 111, etc."""
        return bool(re.search(r'(.)\1{2,}', self.password))

    def detect_sequences(self):
        """Detect sequences: abc, 123, etc."""
        if re.search(r'(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|123|234|345|456|567|678|789)', self.password.lower()):
            return True
        return False

    def crack_time_string(self):
        """Convert guesses to human-readable crack time."""
        # Assume 10^12 guesses/sec for offline GPU attack
        seconds = self.guesses / 1e12

        if seconds < 1:
            return 'Instant'
        if seconds < 60:
            return f'{int(seconds)}s'
        if seconds < 3600:
            return f'{int(seconds/60)}m'
        if seconds < 86400:
            return f'{int(seconds/3600)}h'
        if seconds < 2592000:
            return f'{int(seconds/86400)}d'
        if seconds < 31536000:
            return f'{int(seconds/2592000)}mo'

        years = seconds / 31536000
        if years > 1000000:
            return 'Centuries'
        return f'{int(years)}y'

    def score(self):
        """Return 0-4 score based on guesses needed."""
        entropy = self.calculate_entropy()
        if entropy < 20:
            return 0
        if entropy < 40:
            return 1
        if entropy < 60:
            return 2
        if entropy < 80:
            return 3
        return 4

    def primary_warning(self):
        """Return single most actionable warning."""
        if self.password in COMMON_PASSWORDS:
            return 'This is a commonly-used password found in breach databases.'

        if self.length < 8:
            return 'Too short — minimum 8 characters. Aim for 15+.'

        if len(self.patterns) == 0:
            return None

        # Prioritize warnings by impact
        if 'keyboard' in self.patterns:
            return 'Keyboard pattern detected (qwerty/asdf) — not random enough.'
        if 'date' in self.patterns:
            return 'Contains date pattern — predictable and often tied to personal info.'
        if 'common_word' in self.patterns:
            return 'Contains common words — use unrelated random words instead.'
        if 'l33t' in self.patterns:
            return 'L33t speak — attackers have specialized dictionaries for this.'
        if 'repeats' in self.patterns:
            return 'Repeating characters reduce entropy — vary it up.'
        if 'sequences' in self.patterns:
            return 'Sequential characters detected — not random enough.'

        return None

    def to_dict(self):
        """Return analysis as dictionary for JSON response."""
        entropy = self.calculate_entropy()
        return {
            'password_length': self.length,
            'entropy': round(entropy, 1),
            'entropy_bits': round(entropy),
            'score': self.score(),
            'guesses_needed': round(self.guesses),
            'crack_time': self.crack_time_string(),
            'crack_time_display': self.crack_time_string(),
            'patterns_detected': self.patterns,
            'primary_warning': self.primary_warning(),
            'is_common': self.password in COMMON_PASSWORDS,
            'strength_rating': ['Critical', 'Weak', 'Fair', 'Good', 'Excellent'][self.score()],
        }


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Analyze password strength."""
    data = request.get_json()
    password = data.get('password', '')

    if not password:
        return jsonify({'error': 'Password required'}), 400

    if len(password) > 128:
        return jsonify({'error': 'Password too long (max 128 chars)'}), 400

    analyzer = PasswordAnalyzer(password)
    return jsonify(analyzer.to_dict())


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'password-analyzer'
    })


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Development server - use gunicorn in production
    app.run(debug=True, host='127.0.0.1', port=5000)
