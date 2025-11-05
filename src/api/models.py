"""Pydantic models for API requests and responses"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


# Request Models
class AnalyzeRequest(BaseModel):
    """Request to analyze a JWT token"""
    token: str = Field(..., description="JWT token to analyze")


class VerifyRequest(BaseModel):
    """Request to verify JWT signature"""
    token: str = Field(..., description="JWT token to verify")
    key: str = Field(..., description="Secret key or public key")
    algorithm: Optional[str] = Field(None, description="Force specific algorithm")


class CrackRequest(BaseModel):
    """Request to crack JWT secret"""
    token: str = Field(..., description="JWT token to crack")
    wordlist: Optional[str] = Field(None, description="Custom wordlist (one secret per line)")
    use_common: bool = Field(True, description="Try common weak secrets")
    workers: Optional[int] = Field(None, description="Number of worker processes")


class ForgeRequest(BaseModel):
    """Request to forge/manipulate JWT token"""
    token: str
    mode: str  # none, modify, confusion, custom, escalate
    claims: Optional[Dict[str, Any]] = None
    secret: Optional[str] = None
    header: Optional[Dict[str, Any]] = None
    payload: Optional[Dict[str, Any]] = None
    public_key: Optional[str] = None
    escalation_type: Optional[str] = None


# Response Models
class SecurityWarningResponse(BaseModel):
    """Security warning in analysis"""
    severity: str
    category: str
    message: str
    recommendation: str


class TimestampInfoResponse(BaseModel):
    """Timestamp information"""
    value: int
    human: str
    expired: Optional[bool] = None
    time_remaining: Optional[str] = None
    active: Optional[bool] = None


class AnalyzeResponse(BaseModel):
    """Analysis result"""
    algorithm: str
    algorithm_type: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    warnings: List[SecurityWarningResponse]
    timestamp_info: Dict[str, TimestampInfoResponse]


class VerifyResponse(BaseModel):
    """Verification result"""
    valid: bool
    algorithm: str
    message: str
    key_info: Optional[str] = None


class JobStatusResponse(BaseModel):
    """Job status response"""
    job_id: str
    status: str  # "pending", "running", "completed", "failed"
    progress: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str
    updated_at: str


class CrackStartResponse(BaseModel):
    """Response when crack job is started"""
    job_id: str
    status: str
    message: str


class ErrorResponse(BaseModel):
    """Error response"""
    error: str
    detail: Optional[str] = None


class ForgeResponse(BaseModel):
    """Response from forge operation"""
    success: bool
    token: Optional[str] = None
    header: Optional[Dict[str, Any]] = None
    payload: Optional[Dict[str, Any]] = None
    attack_type: Optional[str] = None
    message: str
