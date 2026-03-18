# SecureScope Deployment Guide

## 1. Prepare Environment
1. Copy `.env.example` to `.env`
2. Set `JWT_SECRET_KEY` and `ENCRYPTION_KEY` securely
3. For `ENCRYPTION_KEY`, run in Python: `from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())`

## 2. Build and Run
`docker compose up --build -d`

## 3. HTTPS Readiness
- Terminate TLS at ingress/reverse proxy
- Replace Nginx server block with certificates (`listen 443 ssl;`)
- Enforce HSTS and redirect HTTP to HTTPS

## 4. Security Checklist
- Rotate secrets regularly
- Restrict DB network access
- Enable centralized log shipping
- Scan dependencies in CI
- Configure backup and disaster recovery
