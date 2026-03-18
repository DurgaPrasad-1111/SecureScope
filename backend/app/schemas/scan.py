from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, field_validator


class ScanCreate(BaseModel):
    domain: str = Field(min_length=3, max_length=255)
    modules: list[
        Literal[
            'port_scan',
            'subdomain_enum',
            'dns_records',
            'tls_check',
            'header_validation',
            'tech_fingerprint',
            'osint_metadata',
            'cookie_flags',
            'directory_enum',
            'admin_panel_probe',
            'rate_limit_probe',
            'xss_probe',
            'sqli_probe',
            'csrf_probe',
        ]
    ] = Field(min_length=1)

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        domain = v.strip().lower()
        if domain.startswith('http://') or domain.startswith('https://'):
            domain = domain.split('://', 1)[1]
        domain = domain.split('/', 1)[0]

        if len(domain) < 3 or '..' in domain or ' ' in domain:
            raise ValueError('Invalid domain format')

        import re
        if not re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', domain):
            raise ValueError('Invalid domain format')
        return domain


class ScanOut(BaseModel):
    id: int
    domain: str
    status: str
    risk_score: int
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None

    class Config:
        from_attributes = True
