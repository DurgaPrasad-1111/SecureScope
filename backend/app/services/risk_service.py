from typing import Any


STRIDE_MAP = {
    'open_port': 'Tampering',
    'missing_hsts': 'Information Disclosure',
    'missing_csp': 'Information Disclosure',
    'weak_tls': 'Spoofing',
    'subdomain_exposure': 'Repudiation',
    'subdomain_discovered': 'Information Disclosure',
    'subdomain_none_found': 'Information Disclosure',
    'whois_exposure': 'Information Disclosure',
    'tech_fingerprint': 'Information Disclosure',
    'cookie_flags_weak': 'Information Disclosure',
    'sensitive_paths_exposed': 'Elevation of Privilege',
    'admin_panel_exposed': 'Elevation of Privilege',
    'rate_limit_absent': 'Denial of Service',
    'xss_reflection_hint': 'Tampering',
    'sqli_error_hint': 'Tampering',
    'csrf_token_hint_missing': 'Spoofing',
}


def map_stride(finding_type: str) -> str:
    return STRIDE_MAP.get(finding_type, 'Information Disclosure')


SEVERITY_SCORE = {'Critical': 10, 'High': 8, 'Medium': 5, 'Low': 2, 'Info': 1}


def severity_from_score(score: int) -> str:
    if score >= 85:
        return 'Critical'
    if score >= 65:
        return 'High'
    if score >= 40:
        return 'Medium'
    if score >= 15:
        return 'Low'
    return 'Info'


def risk_score(findings: list[dict[str, Any]]) -> int:
    weights = {
        'open_port': 0.15,
        'tls': 0.20,
        'headers': 0.20,
        'dns': 0.10,
        'subdomain': 0.10,
        'osint': 0.05,
        'app': 0.20,
    }
    total = 0.0
    for f in findings:
        base = SEVERITY_SCORE.get(f['severity'], 1) * 10
        total += base * weights.get(f.get('category', 'headers'), 0.05)
    return min(100, int(total))
