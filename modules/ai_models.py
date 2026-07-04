"""
AI Response Models - Pydantic models
Used to parse AI outputs in a type-safe way.
"""

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class AIAnalysisResponse(BaseModel):
    """
    Pydantic model for the AI analysis output.
    """

    risk_score: str = Field(..., description="Risk level: Low, Medium or High")
    user_entity: str = Field(..., description="Detected username or machine name")
    summary: str = Field(..., description="Non-technical, clear explanation of the event")
    advice: str = Field(..., description="What should be done in this case? Practical recommendations")
    event_id_explanation: Optional[str] = Field(
        default=None, description="Educational explanation about the Event ID (optional)"
    )

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, v: str) -> str:
        """
        Normalize the risk level to a canonical English value.
        Accepts both English and legacy Turkish inputs and always
        returns one of: "Low", "Medium", "High".
        """
        if not v:
            return "Medium"  # Default for empty value

        v_lower = str(v).strip().lower()

        # Exact match check (takes priority)
        if v_lower in ("low", "düşük"):
            return "Low"
        elif v_lower in ("medium", "orta"):
            return "Medium"
        elif v_lower in ("high", "yüksek"):
            return "High"

        # Substring check (fallback)
        if "yüksek" in v_lower or "high" in v_lower:
            return "High"
        elif "orta" in v_lower or "medium" in v_lower:
            return "Medium"
        elif "düşük" in v_lower or "low" in v_lower:
            return "Low"

        # Default for unrecognized value
        return "Medium"

    def to_markdown(self) -> str:
        """
        Returns output in Markdown format (for Dashboard compatibility).
        """
        parts = []

        if self.event_id_explanation:
            parts.append(f"🆔 Event ID Explained\n{self.event_id_explanation}\n")

        parts.append("🕵️‍♂️ Analysis")
        parts.append(f"User/Entity: {self.user_entity}")
        parts.append(f"Summary: {self.summary}")
        parts.append(f"Risk Level: {self.risk_score}\n")

        parts.append(f"💡 Recommendation\n{self.advice}")

        return "\n".join(parts)
