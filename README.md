# SecureScope - Web Reconnaissance & Risk Intelligence Platform

SecureScope is a production-ready full-stack application for web reconnaissance, misconfiguration detection, weighted risk scoring, STRIDE threat classification, and remediation-focused reporting.

## Stack
- Frontend: React + Vite
- Backend: FastAPI + SQLAlchemy
- DB: PostgreSQL
- Reverse Proxy: Nginx
- Containerization: Docker + Docker Compose

## Folder Structure
```
backend/
  app/
    api/v1/routes/
    core/
    middleware/
    models/
    schemas/
    services/
    main.py
  Dockerfile
  requirements.txt
frontend/
  src/
    api/
    components/
    context/
    pages/
    routes/
  Dockerfile
  package.json
nginx/
  nginx.conf
docker-compose.yml
.env.example
database_schema.sql
DEPLOYMENT.md
```

## Security Controls Implemented
- Argon2 password hashing
- JWT access + refresh token flow with expiry
- Refresh token revocation via blacklist
- RBAC at API/service/frontend route levels
- Least privilege role hierarchy (Admin, Security Analyst, Developer, Viewer)
- Pydantic schema input validation
- ORM-based DB operations (SQL injection mitigation)
- CORS policy restrictions
- CSRF header verification for state-changing endpoints
- HTTP security headers middleware
- Secure error responses (generic in production)
- Rate limiting (`slowapi`)
- `.env`-based secrets/config
- Audit logging
- Sensitive field encryption using Fernet
- Secure report file handling with role-based access

## Recon Features
- Safe TCP port scan over controlled common ports
- Subdomain enumeration
- DNS record inspection (A, MX, TXT, NS)
- TLS configuration check
- HTTP security header validation
- Technology fingerprinting (`Server`, `X-Powered-By`)
- OSINT metadata collection (WHOIS)
- Weighted risk scoring engine
- STRIDE classification mapping
- CVSS-inspired severity scoring

## Run Locally
1. Copy `.env.example` to `.env`
2. Set secrets in `.env`
3. Start services:
   `docker compose up --build`
4. Access app at `http://localhost`

## API Notes
- Base API: `/api/v1`
- Register: `POST /auth/register`
- Login: `POST /auth/login`
- Run scan: `POST /scans` (Security Analyst+)
- Reports: `GET /reports` and `GET /reports/{id}/download`

## Default Role Model
- Admin: full access
- Security Analyst: run scans + view reports
- Developer: view vulnerabilities + remediation
- Viewer: read-only reports/dashboard

## SSDLC and OWASP Alignment
- Threat-informed design with STRIDE tagging
- Secure defaults and minimal data exposure
- Centralized validation and exception handling
- Auditable security events
- Deployment hardening guidance
- CI pipeline for repeatable build checks
