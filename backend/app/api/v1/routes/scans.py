import json
import os
import secrets
import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.csrf import enforce_csrf
from app.core.database import get_db
from app.core.rbac import ensure_role
from app.deps import get_current_user, security
from app.models import Finding, Scan, Report, AuditLog
from app.schemas.scan import ScanCreate, ScanOut
from app.services.audit_service import write_audit_log
from app.services.recon_service import recon_service
from app.services.report_service import report_service
from app.services.risk_service import map_stride, risk_score

router = APIRouter()


def _remove_report_file(path: str) -> bool:
    base_reports_dir = os.path.abspath(settings.report_storage_path)
    try:
        report_path = os.path.abspath(path)
        if os.path.commonpath([base_reports_dir, report_path]) == base_reports_dir and os.path.exists(report_path):
            os.remove(report_path)
            return True
    except Exception:
        return False
    return False


def _record_module(module_results: dict, module_key: str, started: float, output: dict | list):
    module_results[module_key] = {
        'duration_ms': int((time.perf_counter() - started) * 1000),
        'raw': output,
    }


@router.post('/', response_model=ScanOut)
def run_scan(request: Request, payload: ScanCreate, credentials=Depends(security), db: Session = Depends(get_db)):
    user = get_current_user(credentials, db)
    enforce_csrf(request, user._claims)
    ensure_role(user.role.name, 'Security Analyst')

    normalized_domain = payload.domain.strip().lower()
    modules = payload.modules

    scan = Scan(domain=normalized_domain, status='running', requested_by=user.id, started_at=datetime.now(timezone.utc))
    db.add(scan)
    db.commit()
    db.refresh(scan)

    findings = []
    module_results: dict = {}
    scan_started = time.perf_counter()

    if 'port_scan' in modules:
        t = time.perf_counter()
        open_ports = recon_service.scan_ports(normalized_domain)
        _record_module(module_results, 'port_scan', t, {'open_ports': open_ports})
        for p in open_ports:
            findings.append({
                'category': 'open_port',
                'finding_type': 'open_port',
                'title': f'Exposed service on port {p}',
                'description': f'Port {p} is reachable from network scan.',
                'severity': 'Medium' if p in [80, 443] else 'High',
                'remediation': 'Restrict external exposure using firewall and network ACL policies.',
                'evidence': json.dumps({'port': p})
            })

    if 'subdomain_enum' in modules:
        t = time.perf_counter()
        subdomains = recon_service.enumerate_subdomains(normalized_domain)
        _record_module(module_results, 'subdomain_enum', t, {'subdomains': subdomains})
        if subdomains:
            findings.append({
                'category': 'subdomain',
                'finding_type': 'subdomain_discovered',
                'title': 'Discoverable subdomains identified',
                'description': f'{len(subdomains)} subdomains discovered during enumeration.',
                'severity': 'Info' if len(subdomains) <= 3 else 'Medium',
                'remediation': 'Review external-facing subdomains; remove stale records and enforce consistent hardening policies.',
                'evidence': json.dumps({'subdomains': subdomains})
            })
        else:
            findings.append({
                'category': 'subdomain',
                'finding_type': 'subdomain_none_found',
                'title': 'No common subdomains discovered',
                'description': 'Enumeration of common subdomain names did not return records.',
                'severity': 'Info',
                'remediation': 'Continue monitoring DNS exposure; consider periodic passive DNS assessments for shadow assets.',
                'evidence': json.dumps({'subdomains': []})
            })

    if 'dns_records' in modules:
        t = time.perf_counter()
        dns_info = recon_service.dns_records(normalized_domain)
        _record_module(module_results, 'dns_records', t, dns_info)
        if not dns_info.get('TXT'):
            findings.append({
                'category': 'dns',
                'finding_type': 'dns_missing_txt',
                'title': 'No TXT security records detected',
                'description': 'SPF/DMARC-like controls may be absent.',
                'severity': 'Low',
                'remediation': 'Add SPF, DKIM, and DMARC TXT records.',
                'evidence': json.dumps({'txt_records': dns_info.get('TXT', [])})
            })

    if 'tls_check' in modules:
        t = time.perf_counter()
        tls_info = recon_service.check_tls(normalized_domain)
        _record_module(module_results, 'tls_check', t, tls_info)
        if not tls_info.get('valid') or tls_info.get('version') in {'TLSv1', 'TLSv1.1'}:
            findings.append({
                'category': 'tls',
                'finding_type': 'weak_tls',
                'title': 'Weak or invalid TLS configuration',
                'description': 'TLS endpoint is invalid or using deprecated version.',
                'severity': 'High',
                'remediation': 'Enforce TLS 1.2+ and rotate certificates with modern cipher suites.',
                'evidence': json.dumps(tls_info)
            })

    headers_info = None
    if 'header_validation' in modules or 'tech_fingerprint' in modules or 'cookie_flags' in modules:
        t = time.perf_counter()
        headers_info = recon_service.header_check(normalized_domain)
        _record_module(module_results, 'header_validation', t, headers_info)

    if 'header_validation' in modules and headers_info is not None:
        if 'Strict-Transport-Security' in headers_info.get('missing', []):
            findings.append({
                'category': 'headers',
                'finding_type': 'missing_hsts',
                'title': 'HSTS header missing',
                'description': 'HTTP Strict-Transport-Security header not detected.',
                'severity': 'High',
                'remediation': 'Enable HSTS with includeSubDomains and long max-age.',
                'evidence': json.dumps({'missing': ['Strict-Transport-Security']})
            })
        if 'Content-Security-Policy' in headers_info.get('missing', []):
            findings.append({
                'category': 'headers',
                'finding_type': 'missing_csp',
                'title': 'CSP header missing',
                'description': 'Content-Security-Policy header not detected.',
                'severity': 'Medium',
                'remediation': 'Define strict CSP to reduce script injection risks.',
                'evidence': json.dumps({'missing': ['Content-Security-Policy']})
            })

    if 'tech_fingerprint' in modules and headers_info is not None:
        tech = headers_info.get('tech', {})
        t = time.perf_counter()
        _record_module(module_results, 'tech_fingerprint', t, tech)
        findings.append({
            'category': 'headers',
            'finding_type': 'tech_fingerprint',
            'title': 'Technology fingerprint collected',
            'description': 'Server stack metadata could aid attacker reconnaissance.',
            'severity': 'Info',
            'remediation': 'Minimize version leakage and standardize server banner policies.',
            'evidence': json.dumps(tech),
        })

    if 'osint_metadata' in modules:
        t = time.perf_counter()
        osint = recon_service.osint_metadata(normalized_domain)
        _record_module(module_results, 'osint_metadata', t, osint)
        if osint.get('emails'):
            findings.append({
                'category': 'osint',
                'finding_type': 'whois_exposure',
                'title': 'WHOIS contact metadata exposure',
                'description': 'Public metadata includes contact information.',
                'severity': 'Low',
                'remediation': 'Use privacy-protected registration contact details where policy allows.',
                'evidence': json.dumps({'emails': osint.get('emails', [])})
            })

    if 'cookie_flags' in modules:
        t = time.perf_counter()
        cookie_info = recon_service.cookie_flag_check(normalized_domain)
        _record_module(module_results, 'cookie_flags', t, cookie_info)
        if cookie_info.get('insecure'):
            findings.append({
                'category': 'headers',
                'finding_type': 'cookie_flags_weak',
                'title': 'Insecure cookie flags detected',
                'description': 'One or more cookies are missing Secure/HttpOnly/SameSite attributes.',
                'severity': 'Medium',
                'remediation': 'Set Secure, HttpOnly and SameSite attributes for session and sensitive cookies.',
                'evidence': json.dumps(cookie_info.get('insecure', [])[:5]),
            })

    if 'directory_enum' in modules:
        t = time.perf_counter()
        dirs = recon_service.directory_enum(normalized_domain)
        _record_module(module_results, 'directory_enum', t, dirs)
        if dirs.get('found'):
            findings.append({
                'category': 'headers',
                'finding_type': 'sensitive_paths_exposed',
                'title': 'Potentially sensitive paths are reachable',
                'description': 'Directory enumeration found potentially sensitive endpoints.',
                'severity': 'Medium',
                'remediation': 'Restrict or harden exposed administrative and sensitive routes.',
                'evidence': json.dumps(dirs.get('found', [])[:8]),
            })

    if 'admin_panel_probe' in modules:
        t = time.perf_counter()
        admin = recon_service.admin_panel_probe(normalized_domain)
        _record_module(module_results, 'admin_panel_probe', t, admin)
        if admin.get('exposed'):
            findings.append({
                'category': 'headers',
                'finding_type': 'admin_panel_exposed',
                'title': 'Admin panel endpoint appears exposed',
                'description': 'Known administrative paths returned accessible responses.',
                'severity': 'High',
                'remediation': 'Restrict admin panel access by IP/VPN and enforce MFA.',
                'evidence': json.dumps(admin.get('exposed', [])[:8]),
            })

    if 'rate_limit_probe' in modules:
        t = time.perf_counter()
        rl = recon_service.rate_limit_probe(normalized_domain)
        _record_module(module_results, 'rate_limit_probe', t, rl)
        if not rl.get('has_rate_limit_response'):
            findings.append({
                'category': 'headers',
                'finding_type': 'rate_limit_absent',
                'title': 'Rate-limit behavior not observed',
                'description': 'Burst requests did not trigger throttling responses (429).',
                'severity': 'Medium',
                'remediation': 'Apply endpoint-level and global rate limiting for abuse control.',
                'evidence': json.dumps({'statuses': rl.get('statuses', [])}),
            })

    if 'xss_probe' in modules:
        t = time.perf_counter()
        xss = recon_service.reflected_xss_probe(normalized_domain)
        _record_module(module_results, 'xss_probe', t, xss)
        if xss.get('reflected'):
            findings.append({
                'category': 'headers',
                'finding_type': 'xss_reflection_hint',
                'title': 'Reflected script payload indicator observed',
                'description': 'Probe payload appears reflected in response. Manual confirmation is required.',
                'severity': 'High',
                'remediation': 'Enforce output encoding and input sanitization; deploy CSP defense-in-depth.',
                'evidence': json.dumps(xss),
            })

    if 'sqli_probe' in modules:
        t = time.perf_counter()
        sqli = recon_service.sqli_probe(normalized_domain)
        _record_module(module_results, 'sqli_probe', t, sqli)
        if sqli.get('error_markers'):
            findings.append({
                'category': 'headers',
                'finding_type': 'sqli_error_hint',
                'title': 'SQL error pattern hints in response',
                'description': 'Probe generated response patterns commonly associated with SQL errors. Manual confirmation is required.',
                'severity': 'High',
                'remediation': 'Use parameterized queries and suppress DB error details from responses.',
                'evidence': json.dumps(sqli),
            })

    if 'csrf_probe' in modules:
        t = time.perf_counter()
        csrf = recon_service.csrf_hint_probe(normalized_domain)
        _record_module(module_results, 'csrf_probe', t, csrf)
        if csrf.get('has_form') and not csrf.get('has_csrf_hint'):
            findings.append({
                'category': 'headers',
                'finding_type': 'csrf_token_hint_missing',
                'title': 'Form detected without visible CSRF token indicator',
                'description': 'A form was detected but no obvious CSRF token marker was found. Manual validation required.',
                'severity': 'Medium',
                'remediation': 'Implement anti-CSRF token validation for state-changing form actions.',
                'evidence': json.dumps(csrf),
            })

    for item in findings:
        stride = map_stride(item['finding_type'])
        db.add(Finding(
            scan_id=scan.id,
            finding_type=item['finding_type'],
            title=item['title'],
            description=item['description'],
            severity=item['severity'],
            stride=stride,
            remediation=item['remediation'],
            evidence=item.get('evidence'),
        ))

    score = risk_score(findings)
    scan.risk_score = score
    scan.status = 'completed'
    scan.finished_at = datetime.now(timezone.utc)

    total_duration_ms = int((time.perf_counter() - scan_started) * 1000)
    report_findings = [{**f, 'stride': map_stride(f['finding_type'])} for f in findings]
    report_path = report_service.generate_report(
        scan.id,
        scan.domain,
        score,
        report_findings,
        secrets.token_hex(8),
        module_results=module_results,
        duration_ms=total_duration_ms,
    )

    db.add(Report(scan_id=scan.id, generated_by=user.id, file_path=report_path))
    db.commit()

    write_audit_log(
        db,
        user.id,
        'run_scan',
        'scans',
        {
            'scan_id': scan.id,
            'domain': scan.domain,
            'modules': modules,
            'module_results': module_results,
            'duration_ms': total_duration_ms,
        },
    )
    return scan


@router.get('/', response_model=list[ScanOut])
def scan_history(credentials=Depends(security), db: Session = Depends(get_db)):
    user = get_current_user(credentials, db)
    ensure_role(user.role.name, 'Developer')

    query = db.query(Scan)
    if user.role.name != 'Admin':
        query = query.filter(Scan.requested_by == user.id)
    scans = query.order_by(Scan.created_at.desc()).all()
    return scans


@router.get('/{scan_id}')
def scan_details(scan_id: int, credentials=Depends(security), db: Session = Depends(get_db)):
    user = get_current_user(credentials, db)
    ensure_role(user.role.name, 'Developer')

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail='Scan not found')
    if user.role.name != 'Admin' and scan.requested_by != user.id:
        raise HTTPException(status_code=403, detail='Access denied for this scan')

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    audit = db.query(AuditLog).filter(AuditLog.action == 'run_scan').order_by(AuditLog.created_at.desc()).all()
    module_results = {}
    duration_ms = None
    for row in audit:
        try:
            obj = json.loads(row.log_metadata or '{}')
            if obj.get('scan_id') == scan_id:
                module_results = obj.get('module_results', {})
                duration_ms = obj.get('duration_ms')
                break
        except Exception:
            continue

    return {
        'scan': ScanOut.model_validate(scan),
        'findings': [
            {
                'id': f.id,
                'finding_type': f.finding_type,
                'title': f.title,
                'description': f.description,
                'severity': f.severity,
                'stride': f.stride,
                'remediation': f.remediation,
                'evidence': f.evidence,
                'created_at': f.created_at,
            }
            for f in findings
        ],
        'module_results': module_results,
        'duration_ms': duration_ms,
    }


@router.delete('/')
def clear_scans(request: Request, credentials=Depends(security), db: Session = Depends(get_db)):
    user = get_current_user(credentials, db)
    enforce_csrf(request, user._claims)
    ensure_role(user.role.name, 'Developer')

    scans_query = db.query(Scan)
    if user.role.name != 'Admin':
        scans_query = scans_query.filter(Scan.requested_by == user.id)

    target_scans = scans_query.all()
    scan_ids = [s.id for s in target_scans]

    if not scan_ids:
        return {'detail': 'No previous scans to clear', 'scope': 'all' if user.role.name == 'Admin' else 'mine'}

    target_reports = db.query(Report).filter(Report.scan_id.in_(scan_ids)).all()
    deleted_files = 0
    for r in target_reports:
        if _remove_report_file(r.file_path):
            deleted_files += 1

    findings_deleted = db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).delete(synchronize_session=False)
    reports_deleted = db.query(Report).filter(Report.scan_id.in_(scan_ids)).delete(synchronize_session=False)
    scans_deleted = db.query(Scan).filter(Scan.id.in_(scan_ids)).delete(synchronize_session=False)
    db.commit()

    write_audit_log(
        db,
        user.id,
        'clear_scans',
        'scans',
        {
            'scope': 'all' if user.role.name == 'Admin' else 'mine',
            'scans_deleted': scans_deleted,
            'findings_deleted': findings_deleted,
            'reports_deleted': reports_deleted,
            'report_files_deleted': deleted_files,
        },
    )

    return {
        'detail': 'Previous scans cleared successfully',
        'scope': 'all' if user.role.name == 'Admin' else 'mine',
        'scans_deleted': scans_deleted,
        'findings_deleted': findings_deleted,
        'reports_deleted': reports_deleted,
        'report_files_deleted': deleted_files,
    }
