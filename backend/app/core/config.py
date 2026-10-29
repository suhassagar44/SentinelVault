"""Configuration loading, validation, and fail-closed privacy guards."""

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional
import yaml
from pydantic import BaseModel, Field, field_validator


class AppConfig(BaseModel):
    name: str = Field(..., min_length=1)
    short_name: str = Field(..., min_length=1)
    team_id: str = Field(..., min_length=1)
    phase: str = Field(..., min_length=1)
    version: str = Field(..., min_length=1)
    environment: str = Field(default="development")
    config_version: str = Field(..., min_length=1)


class ServerConfig(BaseModel):
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000)
    cors_origins: List[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    @field_validator("port")
    @classmethod
    def validate_port_range(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"Port must be between 1 and 65535, got {v}")
        return v


class DatabaseConfig(BaseModel):
    enabled: bool = Field(default=False)
    dialect: str = Field(default="sqlite")
    url: str = Field(default="sqlite:///./hotfix_dev.db")


class LoggingConfig(BaseModel):
    level: str = Field(default="INFO")
    structured: bool = Field(default=True)

    @field_validator("level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper_v = v.upper()
        if upper_v not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return upper_v


class PrivacyReleaseConfig(BaseModel):
    enabled: bool = Field(default=False)
    disabled_reason: str = Field(
        default="Differential privacy engine and official accounting specification not yet configured"
    )


class ApplicationSettings(BaseModel):
    app: AppConfig
    server: ServerConfig
    database: DatabaseConfig
    logging: LoggingConfig
    privacy_release: PrivacyReleaseConfig


class SpecInfo(BaseModel):
    status: str = Field(default="NOT_CONFIGURED")
    version: Optional[str] = None
    source: Optional[str] = None
    notes: Optional[str] = None


class PrivacySpec(BaseModel):
    unit_of_privacy: Optional[str] = None
    adjacency: Optional[str] = None
    accounting_method: Optional[str] = None
    composition_rules: Optional[str] = None
    cap_epsilon: Optional[float] = None
    clipping_assumptions: Optional[str] = None
    risk_metric: Optional[str] = None
    risk_threshold: Optional[float] = None

    @field_validator("cap_epsilon")
    @classmethod
    def validate_cap_epsilon(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and v <= 0:
            raise ValueError("Cumulative epsilon cap must be strictly positive")
        return v


class ReleaseSpec(BaseModel):
    enabled: bool = Field(default=False)
    disabled_reason: Optional[str] = None


class SpecSettings(BaseModel):
    spec: SpecInfo
    privacy: PrivacySpec
    release: ReleaseSpec


class Settings:
    """Consolidated application settings with strict validation and fail-closed privacy gates."""

    def __init__(self, app_yaml_path: Optional[Path] = None, spec_yaml_path: Optional[Path] = None):
        self.root_dir = self._find_repo_root()
        self.app_yaml_path = app_yaml_path or self._resolve_path(
            os.getenv("HOTFIX_CONFIG_PATH", "config/app.yaml")
        )
        self.spec_yaml_path = spec_yaml_path or self._resolve_path(
            os.getenv("HOTFIX_SPEC_PATH", "config/spec.yaml")
        )

        self.app_config: ApplicationSettings = self._load_app_config(self.app_yaml_path)
        self.spec_config: SpecSettings = self._load_spec_config(self.spec_yaml_path)

        # Dynamically append CORS origins from environment variables if provided
        env_cors = os.getenv("HOTFIX_CORS_ORIGIN") or os.getenv("HOTFIX_CORS_ORIGINS")
        if env_cors:
            for origin in env_cors.split(","):
                cleaned = origin.strip()
                if cleaned and cleaned not in self.app_config.server.cors_origins:
                    self.app_config.server.cors_origins.append(cleaned)

        # Enforce fail-closed privacy invariants
        self._enforce_privacy_release_invariants()

    def _find_repo_root(self) -> Path:
        """Find the repository root containing config/app.yaml."""
        current = Path(__file__).resolve().parent
        for _ in range(5):
            if (current / "config" / "app.yaml").exists() or (current / "backend").exists():
                return current
            if current.parent == current:
                break
            current = current.parent
        return Path.cwd()

    def _resolve_path(self, rel_or_abs: str) -> Path:
        p = Path(rel_or_abs)
        if p.is_absolute() and p.exists():
            return p
        # Check candidates across working directory, repo root, and backend module paths
        candidates = [
            Path.cwd() / p,
            self.root_dir / p,
            self.root_dir / "backend" / p,
            Path(__file__).resolve().parent.parent.parent / p,
            Path(__file__).resolve().parent.parent.parent.parent / p,
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return p if p.is_absolute() else (self.root_dir / p)

    def _load_app_config(self, path: Path) -> ApplicationSettings:
        if not path.exists():
            raise FileNotFoundError(f"Application configuration file not found at: {path}")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                raise ValueError(f"Application configuration at {path} must be a valid YAML mapping")
            return ApplicationSettings(**data)
        except yaml.YAMLError as e:
            raise ValueError(f"Malformed YAML in application config {path}: {e}") from e

    def _load_spec_config(self, path: Path) -> SpecSettings:
        if not path.exists():
            raise FileNotFoundError(f"Privacy specification file not found at: {path}")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                raise ValueError(f"Privacy specification at {path} must be a valid YAML mapping")
            return SpecSettings(**data)
        except yaml.YAMLError as e:
            raise ValueError(f"Malformed YAML in privacy spec {path}: {e}") from e

    def _enforce_privacy_release_invariants(self) -> None:
        """Enforces that privacy releases cannot be enabled without a complete, verified official specification."""
        release_requested = (
            self.app_config.privacy_release.enabled or self.spec_config.release.enabled
        )

        if release_requested:
            # Check official specification completeness
            is_configured = self.spec_config.spec.status == "CONFIGURED"
            has_version = bool(self.spec_config.spec.version)
            has_unit = bool(self.spec_config.privacy.unit_of_privacy)
            has_method = bool(self.spec_config.privacy.accounting_method)
            has_valid_epsilon = (
                self.spec_config.privacy.cap_epsilon is not None
                and 0 < self.spec_config.privacy.cap_epsilon <= 5.0
            )

            if not (is_configured and has_version and has_unit and has_method and has_valid_epsilon):
                raise ValueError(
                    "Security Violation: Cannot enable privacy releases. "
                    "The official privacy accounting specification is incomplete or unconfigured. "
                    "Fail-closed policy strictly prohibits releases without an approved specification."
                )

    @property
    def is_privacy_release_ready(self) -> bool:
        """
        Determines whether privacy releases are operational.
        In Phase 1, the differential privacy engine is NOT implemented.
        Therefore, this always returns False in Phase 1, regardless of configuration.
        """
        if self.app_config.app.phase == "Phase 1":
            return False
        return (
            self.app_config.privacy_release.enabled
            and self.spec_config.release.enabled
            and self.spec_config.spec.status == "CONFIGURED"
        )


@lru_cache()
def get_settings() -> Settings:
    """Cached factory function for application settings."""
    return Settings()

