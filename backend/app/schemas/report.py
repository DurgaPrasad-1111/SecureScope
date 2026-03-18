from datetime import datetime
from pydantic import BaseModel


class ReportOut(BaseModel):
    id: int
    scan_id: int
    file_path: str
    created_at: datetime

    class Config:
        from_attributes = True
