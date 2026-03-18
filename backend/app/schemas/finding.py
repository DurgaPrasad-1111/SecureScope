from datetime import datetime
from pydantic import BaseModel


class FindingOut(BaseModel):
    id: int
    finding_type: str
    title: str
    description: str
    severity: str
    stride: str
    remediation: str
    evidence: str | None
    created_at: datetime

    class Config:
        from_attributes = True
