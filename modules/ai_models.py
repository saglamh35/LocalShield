"""
AI Response Models - Pydantic modelleri
AI çıktılarını type-safe şekilde parse etmek için
"""
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class AIAnalysisResponse(BaseModel):
    """
    AI analiz çıktısı için Pydantic modeli
    """
    risk_score: str = Field(
        ...,
        description="Risk seviyesi: Düşük, Orta veya Yüksek (İngilizce: Low, Medium, High da kabul edilir)"
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
        """
        Risk seviyesini normalize et
        İngilizce ve Türkçe değerleri Türkçe'ye çevirir
        """
        if not v:
            return "Orta"  # Boş değer için varsayılan
        
        v_clean = str(v).strip()
        v_lower = v_clean.lower()
        
        # Tam eşleşme kontrolü (öncelikli)
        if v_lower == "low" or v_lower == "düşük":
            return "Düşük"
        elif v_lower == "medium" or v_lower == "orta":
            return "Orta"
        elif v_lower == "high" or v_lower == "yüksek":
            return "Yüksek"
        
        # İçerik kontrolü (fallback)
        if 'yüksek' in v_lower or 'high' in v_lower:
            return "Yüksek"
        elif 'orta' in v_lower or 'medium' in v_lower:
            return "Orta"
        elif 'düşük' in v_lower or 'low' in v_lower:
            return "Düşük"
        
        # Tanınmayan değer için varsayılan
        return "Orta"
    
    def to_markdown(self) -> str:
        """
        Markdown formatında çıktı döndürür (Dashboard uyumluluğu için)
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

