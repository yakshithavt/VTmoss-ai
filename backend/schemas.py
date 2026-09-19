from pydantic import BaseModel, Field
from typing import Optional


class CaseCreate(BaseModel):
    case_id: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9\-_]+$")
    title: str = Field(..., min_length=1, max_length=200)
    evidence_source: Optional[str] = None
    investigation_type: Optional[str] = None
