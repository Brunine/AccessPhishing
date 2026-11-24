"""Request/response models for all endpoints."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

FuzzMode = Literal[
    "addition",
    "hyphenation",
    "tld-swap",
    "bitsquatting",
    "omission",
    "repetition",
    "replacement",
]

DEFAULT_MODES: list[FuzzMode] = [
    "addition",
    "hyphenation",
    "tld-swap",
    "bitsquatting",
    "omission",
    "repetition",
    "replacement",
]

_DOMAIN_MAX = 253


def _normalize_domain(value: str) -> str:
    v = value.strip().lower().rstrip(".")
    if not v or len(v) > _DOMAIN_MAX:
        raise ValueError("invalid domain")
    if "/" in v or " " in v or ":" in v:
        raise ValueError("invalid domain")
    if "." not in v:
        raise ValueError("domain must contain a dot")
    for label in v.split("."):
        if not label or len(label) > 63:
            raise ValueError("invalid domain label")
        if not all(c.isalnum() or c == "-" for c in label):
            raise ValueError("invalid characters in domain")
    return v


# --- subdomains ---

class SubdomainsRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def _v(cls, v: str) -> str:
        return _normalize_domain(v)


class SubdomainsResponse(BaseModel):
    domain: str
    source: Literal["subfinder", "crtsh"]
    count: int
    subdomains: list[str]


# --- domain generation ---

class GenerateRequest(BaseModel):
    domain: str
    modes: list[FuzzMode] = Field(default_factory=lambda: list(DEFAULT_MODES))

    @field_validator("domain")
    @classmethod
    def _v(cls, v: str) -> str:
        return _normalize_domain(v)

    @field_validator("modes")
    @classmethod
    def _m(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("at least one mode is required")
        # De-duplicate while preserving order.
        seen: set[str] = set()
        out: list[str] = []
        for m in v:
            if m not in seen:
                seen.add(m)
                out.append(m)
        return out


class Candidate(BaseModel):
    domain: str
    fuzzer: str


class GenerateResponse(BaseModel):
    domain: str
    count: int
    truncated: bool
    candidates: list[Candidate]


# --- suggest (generation + availability in one call) ---

class SuggestRequest(BaseModel):
    domain: str
    modes: list[FuzzMode] = Field(default_factory=lambda: list(DEFAULT_MODES))
    limit: int = Field(default=50, ge=1, le=200)

    @field_validator("domain")
    @classmethod
    def _v(cls, v: str) -> str:
        return _normalize_domain(v)

    @field_validator("modes")
    @classmethod
    def _m(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("at least one mode is required")
        seen: set[str] = set()
        out: list[str] = []
        for m in v:
            if m not in seen:
                seen.add(m)
                out.append(m)
        return out


class SuggestCandidate(BaseModel):
    domain: str
    fuzzer: str
    available: Optional[bool] = None
    status_code: Optional[int] = None


class SuggestResponse(BaseModel):
    domain: str
    count: int
    truncated: bool
    candidates: list[SuggestCandidate]


# --- availability ---

class DomainListRequest(BaseModel):
    domains: list[str] = Field(min_length=1, max_length=500)

    @field_validator("domains")
    @classmethod
    def _v(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for d in v:
            nd = _normalize_domain(d)
            if nd not in seen:
                seen.add(nd)
                out.append(nd)
        return out


class AvailabilityResult(BaseModel):
    domain: str
    available: Optional[bool]
    status_code: Optional[int] = None
    error: Optional[str] = None


class AvailabilityResponse(BaseModel):
    results: list[AvailabilityResult]


# --- reputation ---

class ReputationResult(BaseModel):
    domain: str
    status: Literal["ok", "no_key", "error"]
    malicious: Optional[int] = None
    suspicious: Optional[int] = None
    harmless: Optional[int] = None
    undetected: Optional[int] = None
    status_code: Optional[int] = None
    error: Optional[str] = None
    cached: bool = False


class ReputationResponse(BaseModel):
    results: list[ReputationResult]
