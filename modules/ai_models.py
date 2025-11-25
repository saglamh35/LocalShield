"""
AI Response Models - Pydantic modelleri
AI çıktılarını type-safe şekilde parse etmek için
"""
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator


class AIAnalysisResponse(BaseModel):
    """
    AI analiz çıktısı için Pydantic modeli
    """
    risk_score: Literal["Düşük", "Orta", "Yüksek"] = Field(
        ...,
        description="Risk seviyesi: Düşük, Orta veya Yüksek"
    )
    user_entity: str = Field(
        ...,
        description="Tespit edilen kullanıcı adı veya makine adı"
    )
    summary: str = Field(
        ...,
        description="Olayın teknik olmayan, net Türkçe açıklaması"
    )
    advice: str = Field(
        ...,
        description="Bu durumda ne yapılmalı? Pratik tavsiyeler"
    )
    event_id_explanation: Optional[str] = Field(
        default=None,
        description="Event ID hakkında eğitici açıklama (opsiyonel)"
    )
    
    @field_validator('risk_score')
    @classmethod
    def validate_risk_score(cls, v: str) -> str:
        """Risk seviyesini normalize et"""
        v_lower = v.lower().strip()
        if 'yüksek' in v_lower or 'high' in v_lower:
            return "Yüksek"
        elif 'orta' in v_lower or 'medium' in v_lower:
            return "Orta"
        elif 'düşük' in v_lower or 'low' in v_lower:
            return "Düşük"
        return "Orta"  # Varsayılan
    
    def to_markdown(self) -> str:
        """
        Markdown formatında çıktı döndürür (Dashboard uyumluluğu için)
        """
        parts = []
        
        if self.event_id_explanation:
            parts.append(f"🆔 Event ID Nedir?\n{self.event_id_explanation}\n")
        
        parts.append("🕵️‍♂️ Olay Analizi")
        parts.append(f"Kullanıcı: {self.user_entity}")
        parts.append(f"Durum: {self.summary}")
        parts.append(f"Risk: {self.risk_score}\n")
        
        parts.append(f"💡 Tavsiye\n{self.advice}")
        
        return "\n".join(parts)

