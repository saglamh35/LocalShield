"""
Detection-rule schema — validates YAML rules at load time.

Gives rule authors a clear contract and turns a malformed rule into a skipped
rule with a helpful error, instead of a silently mis-parsed one. Mirrors the
type-safe-validation approach used for AI output in modules/ai_models.py.
"""

from typing import Any, List, Optional, Union

from pydantic import BaseModel, Field, field_validator


class RuleConditions(BaseModel):
    """The 'conditions' block of a detection rule."""

    # event_id may be a single value or a list (OR-match)
    event_id: Optional[Union[str, int, List[Union[str, int]]]] = None
    provider: Optional[str] = None
    message_regex: Optional[str] = None
    command_line_regex: Optional[str] = None
    image_regex: Optional[str] = None
    parent_image_regex: Optional[str] = None
    not_message_regex: Optional[str] = None
    not_command_line_regex: Optional[str] = None
    time_window: int = 60
    threshold: int = 0
    group_by: Optional[str] = None
    correlation: Optional[dict] = None

    model_config = {"extra": "forbid"}  # unknown condition keys are an error


class DetectionRuleSchema(BaseModel):
    """A single detection rule."""

    # id is optional: DetectionRule auto-generates one from the filename if absent.
    id: Optional[str] = None
    name: str = Field(..., min_length=1)
    description: str = ""
    enabled: bool = True
    severity: str = "medium"
    mitre: Union[str, List[str]] = []
    tags: List[str] = []
    conditions: RuleConditions = Field(default_factory=RuleConditions)
    match_message: Optional[str] = None
    filters: dict = {}

    # Legacy fields tolerated for backward compatibility
    risk_level: Optional[str] = None
    mitre_technique: Optional[str] = None
    priority: Optional[str] = None

    model_config = {"extra": "forbid"}

    @field_validator("severity")
    @classmethod
    def _severity_known(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if str(v).lower() not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}, got '{v}'")
        return v


def validate_rule(rule_data: Any) -> None:
    """
    Validate one rule dict against the schema.

    Raises pydantic.ValidationError (or ValueError) if the rule is malformed;
    returns None on success. The caller decides whether to skip or abort.
    """
    DetectionRuleSchema(**rule_data)
