import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'secure', 'account', 'banking',
    'paypal', 'ebayisapi', 'webscr', 'confirm', 'password', 'credential',
    'wallet', 'support', 'service', 'suspended', 'unusual', 'activity'
]

SHORTENING_SERVICES = [
    'bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 'ow.ly', 't.co',
    'tinyurl', 'tr.im', 'is.gd', 'cli.gs', 'yfrog.com', 'migre.me', 'ff.im',
    'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com'
]

FEATURE_NAMES = [
    'url_length',
    'domain_length',
    'num_dots',
    'num_hyphens',
    'num_special_chars',
    'has_ip_address',
    'has_https',
    'suspicious_keyword_count',
    'num_subdomains',
    'is_shortened',
    'has_unusual_port',
    'has_at_symbol',
    'digit_ratio'
]

def extract_url_features(url: str) -> dict:
    """Extracts lexical and structural security features statically from a URL."""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        parsed_url = urlparse('http://' + url)
    else:
        parsed_url = urlparse(url)

    domain = parsed_url.netloc.lower()
    domain_clean = domain.split(':')[0]

    url_length = len(url)
    domain_length = len(domain_clean)
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_special_chars = len(re.findall(r'[@?=%&_~]', url))

    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    has_ip_address = 1 if ip_pattern.match(domain_clean) else 0
    has_https = 1 if parsed_url.scheme == 'https' else 0

    url_lower = url.lower()
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    parts = domain_clean.split('.')
    num_subdomains = max(0, len(parts) - 2) if not has_ip_address else 0
    is_shortened = 1 if any(service in domain_clean for service in SHORTENING_SERVICES) else 0

    port = parsed_url.port
    has_unusual_port = 1 if (port is not None and port not in [80, 443]) else 0
    has_at_symbol = 1 if '@' in url else 0

    digits = sum(c.isdigit() for c in url)
    digit_ratio = round(digits / max(1, url_length), 4)

    return {
        'url_length': url_length,
        'domain_length': domain_length,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_special_chars': num_special_chars,
        'has_ip_address': has_ip_address,
        'has_https': has_https,
        'suspicious_keyword_count': suspicious_keyword_count,
        'num_subdomains': num_subdomains,
        'is_shortened': is_shortened,
        'has_unusual_port': has_unusual_port,
        'has_at_symbol': has_at_symbol,
        'digit_ratio': digit_ratio
    }

def features_to_vector(features_dict: dict) -> list:
    return [features_dict[name] for name in FEATURE_NAMES]
