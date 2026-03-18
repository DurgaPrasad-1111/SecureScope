import re
import socket
import ssl
import time
from datetime import datetime
import dns.resolver
import requests
import whois
from requests import Response


COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 389,
    443, 445, 465, 514, 587, 631, 993, 995, 1433, 1521, 1723, 1883, 2049, 2375, 3000, 3306, 3389,
    5000, 5432, 5900, 6379, 7001, 8000, 8080, 8081, 8443, 9000, 9200, 27017,
]
COMMON_SUBDOMAINS = [
    'www', 'mail', 'dev', 'test', 'api', 'staging', 'admin', 'portal', 'beta', 'app', 'cdn', 'static',
    'auth', 'sso', 'vpn', 'support', 'help', 'blog', 'm', 'uat', 'preprod', 'prod', 'ns1', 'ns2',
]
COMMON_DIRS = ['/admin', '/login', '/dashboard', '/config', '/backup', '/.git', '/api/docs']
ADMIN_PATHS = ['/admin', '/administrator', '/wp-admin', '/manage', '/console']


class ReconService:
    def _request_with_fallback(
        self,
        domain: str,
        path: str = '/',
        method: str = 'GET',
        timeout: int = 8,
        allow_redirects: bool = True,
        params: dict | None = None,
    ) -> tuple[Response | None, str | None]:
        headers = {'User-Agent': 'SecureScope/1.0'}
        clean_path = path if path.startswith('/') else f'/{path}'
        for scheme in ('https', 'http'):
            url = f'{scheme}://{domain}{clean_path}'
            try:
                resp = requests.request(
                    method,
                    url,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    params=params,
                    headers=headers,
                )
                return resp, url
            except Exception:
                continue
        return None, None

    def scan_ports(self, domain: str) -> list[int]:
        open_ports = []
        for port in COMMON_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            try:
                if s.connect_ex((domain, port)) == 0:
                    open_ports.append(port)
            except Exception:
                pass
            finally:
                s.close()
        return open_ports

    def enumerate_subdomains(self, domain: str) -> list[str]:
        found = []
        for sub in COMMON_SUBDOMAINS:
            host = f'{sub}.{domain}'
            try:
                dns.resolver.resolve(host, 'A')
                found.append(host)
            except Exception:
                continue
        return found

    def dns_records(self, domain: str) -> dict:
        output = {}
        for rec in ['A', 'MX', 'TXT', 'NS']:
            try:
                ans = dns.resolver.resolve(domain, rec)
                output[rec] = [str(a) for a in ans]
            except Exception:
                output[rec] = []
        return output

    def check_tls(self, domain: str) -> dict:
        result = {'valid': False, 'version': None, 'expires': None}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                    cert = tls_sock.getpeercert()
                    result['valid'] = True
                    result['version'] = tls_sock.version()
                    result['expires'] = cert.get('notAfter')
        except Exception:
            pass
        return result

    def header_check(self, domain: str) -> dict:
        required = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']
        info = {'missing': [], 'present': {}, 'tech': {}, 'set_cookie': [], 'url': None, 'status': None}
        try:
            resp, final_url = self._request_with_fallback(domain, '/', timeout=8, allow_redirects=True)
            if resp is None:
                info['missing'] = required
                return info
            info['url'] = final_url
            info['status'] = resp.status_code
            headers = resp.headers
            for h in required:
                if h not in headers:
                    info['missing'].append(h)
                else:
                    info['present'][h] = headers.get(h)
            info['tech'] = {
                'Server': headers.get('Server', 'unknown'),
                'X-Powered-By': headers.get('X-Powered-By', 'unknown'),
            }
            if 'Set-Cookie' in headers:
                info['set_cookie'] = [x.strip() for x in headers.get('Set-Cookie', '').split(',') if x.strip()]
        except Exception:
            info['missing'] = required
        return info

    def osint_metadata(self, domain: str) -> dict:
        data = {'registrar': None, 'creation_date': None, 'emails': []}
        try:
            w = whois.whois(domain)
            data['registrar'] = w.registrar
            if isinstance(w.creation_date, list):
                data['creation_date'] = str(w.creation_date[0])
            elif isinstance(w.creation_date, datetime):
                data['creation_date'] = str(w.creation_date)
            emails = w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else [])
            data['emails'] = emails[:3]
        except Exception:
            pass
        return data

    def cookie_flag_check(self, domain: str) -> dict:
        result = {'insecure': [], 'raw': [], 'url': None, 'status': None}
        try:
            resp, final_url = self._request_with_fallback(domain, '/', timeout=8, allow_redirects=True)
            if resp is None:
                return result
            result['url'] = final_url
            result['status'] = resp.status_code
            raw_cookie = resp.headers.get('Set-Cookie', '')
            if raw_cookie:
                cookies = [c.strip() for c in raw_cookie.split(',') if c.strip()]
                result['raw'] = cookies
                for c in cookies:
                    missing = []
                    lc = c.lower()
                    if 'secure' not in lc:
                        missing.append('Secure')
                    if 'httponly' not in lc:
                        missing.append('HttpOnly')
                    if 'samesite=' not in lc:
                        missing.append('SameSite')
                    if missing:
                        result['insecure'].append({'cookie': c[:80], 'missing': missing})
        except Exception:
            pass
        return result

    def directory_enum(self, domain: str) -> dict:
        found = []
        for path in COMMON_DIRS:
            try:
                res, url = self._request_with_fallback(domain, path, timeout=5, allow_redirects=False)
                if res is None:
                    continue
                if res.status_code in {200, 301, 302, 403}:
                    found.append({'path': path, 'status': res.status_code, 'url': url})
            except Exception:
                continue
        return {'found': found}

    def admin_panel_probe(self, domain: str) -> dict:
        exposures = []
        for path in ADMIN_PATHS:
            try:
                res, url = self._request_with_fallback(domain, path, timeout=5, allow_redirects=False)
                if res is None:
                    continue
                if res.status_code in {200, 301, 302}:
                    exposures.append({'path': path, 'status': res.status_code, 'url': url})
            except Exception:
                continue
        return {'exposed': exposures}

    def rate_limit_probe(self, domain: str) -> dict:
        statuses = []
        start = time.time()
        for _ in range(8):
            try:
                r, _ = self._request_with_fallback(domain, '/', timeout=4)
                if r is None:
                    statuses.append(-1)
                    continue
                statuses.append(r.status_code)
            except Exception:
                statuses.append(-1)
        elapsed = time.time() - start
        has_429 = 429 in statuses
        return {'statuses': statuses, 'has_rate_limit_response': has_429, 'elapsed_s': round(elapsed, 2)}

    def reflected_xss_probe(self, domain: str) -> dict:
        payload = '<script>alert(1)</script>'
        marker = 'ss_probe_7781'
        encoded = requests.utils.quote(f'{marker}{payload}', safe='')
        path = f'/?q={encoded}'
        try:
            r, url = self._request_with_fallback(domain, path, timeout=6)
            if r is None:
                return {'url': None, 'status': -1, 'reflected': False}
            body = r.text[:6000]
            reflected = marker in body and payload in body
            return {'url': url, 'status': r.status_code, 'reflected': reflected}
        except Exception:
            return {'url': None, 'status': -1, 'reflected': False}

    def sqli_probe(self, domain: str) -> dict:
        payload = "' OR '1'='1"
        encoded = requests.utils.quote(payload, safe='')
        path = f'/?id={encoded}'
        err_patterns = ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'odbc', 'database error']
        try:
            r, url = self._request_with_fallback(domain, path, timeout=6)
            if r is None:
                return {'url': None, 'status': -1, 'error_markers': []}
            body = r.text.lower()[:6000]
            matched = [p for p in err_patterns if re.search(re.escape(p), body)]
            return {'url': url, 'status': r.status_code, 'error_markers': matched}
        except Exception:
            return {'url': None, 'status': -1, 'error_markers': []}

    def csrf_hint_probe(self, domain: str) -> dict:
        try:
            r, url = self._request_with_fallback(domain, '/', timeout=6)
            if r is None:
                return {'status': -1, 'has_form': False, 'has_csrf_hint': False, 'url': None}
            html = r.text.lower()
            has_form = '<form' in html
            has_csrf = ('csrf' in html and 'token' in html) or 'xsrf' in html
            return {'status': r.status_code, 'has_form': has_form, 'has_csrf_hint': has_csrf, 'url': url}
        except Exception:
            return {'status': -1, 'has_form': False, 'has_csrf_hint': False, 'url': None}


recon_service = ReconService()
