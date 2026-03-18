# SecureScope - Web Reconnaissance & Risk Intelligence Platform

SecureScope is a production-ready full-stack application for web reconnaissance, misconfiguration detection, weighted risk scoring, STRIDE threat classification, and remediation-focused reporting.

## Tech Stack
- **Frontend:** React + Vite
- **Backend:** FastAPI + SQLAlchemy
- **Database:** PostgreSQL
- **Reverse Proxy:** Nginx
- **Containerization:** Docker + Docker Compose

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
- JWT access & refresh token authentication
- Refresh token revocation (blacklist)
- Role-Based Access Control (RBAC)
- Least privilege role hierarchy
- Input validation using Pydantic schemas
- ORM-based database access (SQL injection protection)
- CORS policy enforcement
- CSRF protection for state-changing requests
- HTTP security headers middleware
- Secure error handling (production-safe)
- Rate limiting using `slowapi`
- Environment-based configuration (`.env`)
- Audit logging
- Sensitive data encryption (Fernet)
- Secure report access with role restrictions

## Recon Features
- Controlled TCP port scanning
- Subdomain enumeration
- DNS record analysis (A, MX, TXT, NS)
- TLS/SSL configuration checks
- HTTP security header validation
- Technology fingerprinting
- WHOIS metadata collection
- Risk scoring engine (weighted)
- STRIDE threat classification
- CVSS-inspired severity scoring

## Run Locally
1. Copy `.env.example` to `.env`
2. Configure environment variables
3. Start services:
   ```
   docker compose up --build
   ```
4. Open in browser:
   ```
   http://localhost
   ```

## Role Model
- **Admin:** Full system access
- **Security Analyst:** Run scans and view reports
- **Developer:** View vulnerabilities and fixes
- **Viewer:** Read-only access

## Security & Standards
- STRIDE-based threat modeling
- Secure coding practices (OWASP aligned)
- Centralized validation & error handling
- Audit-ready logging system
- Deployment hardening guidelines
- CI/CD ready structure

## Author
**Durga Prasad**  
B.Tech CSE (Cyber Security)  
Aspiring Software Developer | Security Enthusiast  

## Support
If you like this project, consider giving it a ⭐ on GitHub!
