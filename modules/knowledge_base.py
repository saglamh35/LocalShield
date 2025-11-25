"""
Knowledge Base Module - Hibrit RAG Sistemi
Event ID'ler hakkında bilgi sağlayan bilgi bankası modülü
"""
import json
import os
from typing import Dict, Optional
from pathlib import Path

# Dosya yolları
BASE_DIR = Path(__file__).parent.parent
LOCAL_KNOWLEDGE_PATH = BASE_DIR / "data" / "local_knowledge.json"
EXTERNAL_KNOWLEDGE_PATH = BASE_DIR / "data" / "external_knowledge.json"

class KnowledgeBase:
    """
    Hibrit bilgi bankası sınıfı
    Önce local (özel) bilgilere bakar, bulamazsa external (genel) bilgilere bakar
    """
    
    def __init__(self):
        """KnowledgeBase'yi başlatır ve bilgi dosyalarını yükler"""
        self.local_knowledge = {}
        self.external_knowledge = {}
        self.load_knowledge()
    
    def load_knowledge(self):
        """Hem local hem de external bilgi dosyalarını yükler"""
        
        # --- 1. LOCAL KNOWLEDGE YÜKLEME ---
        try:
            if LOCAL_KNOWLEDGE_PATH.exists():
                with open(LOCAL_KNOWLEDGE_PATH, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Local knowledge genelde {"4625": {...}} formatındadır
                    if isinstance(data, dict):
                        self.local_knowledge = data
                    else:
                        print(f"⚠️ Local knowledge beklenen formatta değil (Dict olmalı).")
                print(f"✅ Local knowledge yüklendi: {len(self.local_knowledge)} Event ID")
            else:
                self.local_knowledge = {}
        except Exception as e:
            print(f"❌ Local knowledge yüklenirken hata: {e}")
            self.local_knowledge = {}
        
        # --- 2. EXTERNAL KNOWLEDGE YÜKLEME ---
        try:
            if EXTERNAL_KNOWLEDGE_PATH.exists():
                with open(EXTERNAL_KNOWLEDGE_PATH, 'r', encoding='utf-8') as f:
                    external_data = json.load(f)
                
                self.external_knowledge = {}
                
                # Paylaştığın JSON formatı bir LİSTE (Array) olduğu için bunu işliyoruz
                if isinstance(external_data, list):
                    for item in external_data:
                        # Her öğenin içinden 'eventID' bilgisini alıp anahtar yapıyoruz
                        # Örn: "eventID": "4798"
                        eid = str(item.get("eventID", "")).strip()
                        if eid:
                            self.external_knowledge[eid] = item
                            
                    print(f"✅ External knowledge yüklendi: {len(self.external_knowledge)} Event ID (List -> Dict dönüşümü yapıldı)")
                
                # Eğer dosya zaten Dict formatındaysa (Eski format)
                elif isinstance(external_data, dict):
                    self.external_knowledge = external_data
                    print(f"✅ External knowledge yüklendi: {len(self.external_knowledge)} Event ID")
                
            else:
                print(f"⚠️ External knowledge dosyası bulunamadı: {EXTERNAL_KNOWLEDGE_PATH}")
                self.external_knowledge = {}
                
        except Exception as e:
            print(f"❌ External knowledge yüklenirken hata: {e}")
            self.external_knowledge = {}
    
    def get_event_info(self, event_id: str) -> Optional[Dict[str, str]]:
        """
        Verilen Event ID için bilgi döndürür.
        Önce local'de arar, bulamazsa external'da arar.
        """
        # Event ID'yi string'e çevir ve temizle
        event_id_str = str(event_id).strip()
        
        # 1. Önce LOCAL knowledge'da ara (Öncelikli)
        if event_id_str in self.local_knowledge:
            info = self.local_knowledge[event_id_str].copy()
            info["source"] = "local"
            # Eksik alanları tamamla
            if "risk_level" not in info: info["risk_level"] = "Yüksek"
            if "advice" not in info: info["advice"] = "Bu olay özel olarak tanımlanmıştır."
            return info
        
        # 2. External knowledge'da ara (GitHub verisi)
        if event_id_str in self.external_knowledge:
            external_info = self.external_knowledge[event_id_str]
            # External JSON yapısı farklı, normalize et
            info = self._normalize_external_info(external_info)
            info["source"] = "external"
            return info
        
        # Bulunamadı
        return None
    
    def _normalize_external_info(self, external_info: any) -> Dict[str, str]:
        """
        External knowledge'dan gelen bilgiyi (GitHub JSON formatı) bizim formatımıza çevirir.
        """
        normalized = {
            "title": "",
            "description": "",
            "risk_level": "Orta",
            "advice": ""
        }
        
        if isinstance(external_info, dict):
            # --- BAŞLIK ---
            # 'name' yoksa 'description'ın ilk cümlesini veya 'subCategory'i kullan
            normalized["title"] = (
                external_info.get("name") or 
                external_info.get("subCategory") or 
                f"Event {external_info.get('eventID')}"
            )
            
            # --- AÇIKLAMA ---
            normalized["description"] = external_info.get("description", "")
            
            # --- RİSK SEVİYESİ ---
            # 'level' veya 'securityMonitoringRecommandation' alanına göre karar ver
            sec_rec = str(external_info.get("securityMonitoringRecommandation", "")).lower()
            level = str(external_info.get("level", "")).lower()
            
            if "yes" in sec_rec or "true" in sec_rec:
                normalized["risk_level"] = "Yüksek"
            elif "error" in level or "critical" in level:
                normalized["risk_level"] = "Yüksek"
            elif "information" in level:
                normalized["risk_level"] = "Düşük"
            
            # --- TAVSİYE (KRİTİK KISIM) ---
            # Senin JSON örneğinde 'advice' alanı var. Onu doğrudan alıyoruz.
            # Yoksa 'recommendation' veya 'securityMonitoringRecommandation' kullanılır.
            
            if "advice" in external_info:
                normalized["advice"] = external_info["advice"]
            elif "recommendation" in external_info:
                normalized["advice"] = external_info["recommendation"]
            else:
                # Tavsiye yoksa genel bir metin oluştur
                normalized["advice"] = "Olayın kaynağını ve kullanıcıyı doğrulayın."

        return normalized
    
    def format_event_info_for_prompt(self, event_id: str, event_info: Dict[str, str]) -> str:
        """
        Event bilgisini AI prompt'una eklemek için formatlar.
        """
        knowledge_note = f"""
[⚠️ ÖNEMLİ BİLGİ BANKASI NOTU - BU BİLGİLERİ AYNEN KULLAN ⚠️]

Event ID {event_id} için kesin bilgiler:
"""
        if event_info.get("title"):
            knowledge_note += f"\n📌 BAŞLIK (Aynen kullan): {event_info['title']}"
        
        if event_info.get("description"):
            knowledge_note += f"\n📝 AÇIKLAMA (Aynen kullan): {event_info['description']}"
        
        if event_info.get("risk_level"):
            knowledge_note += f"\n🚨 RİSK SEVİYESİ (Aynen kullan): {event_info['risk_level']}"
        
        if event_info.get("advice"):
            knowledge_note += f"\n💡 TAVSİYE (Aynen kullan): {event_info['advice']}"
        
        knowledge_note += """

[ÖNEMLİ KURAL]: Yukarıdaki bilgileri kendi cümlelerinle yeniden yazma. 
Bilgi bankasından gelen açıklama ve tavsiyeleri aynen kullan. 
Sadece kullanıcının sorusuna göre formatla, ama içeriği değiştirme.
"""
        return knowledge_note

# --- Global Helper Functions (Eski yapı bozulmasın diye) ---

_knowledge_base_instance = None

def load_knowledge():
    global _knowledge_base_instance
    if _knowledge_base_instance is None:
        _knowledge_base_instance = KnowledgeBase()
    return _knowledge_base_instance

def get_event_info(event_id: str) -> Optional[Dict[str, str]]:
    kb = load_knowledge()
    return kb.get_event_info(event_id)

def format_event_info_for_prompt(event_id: str, event_info: Dict[str, str]) -> str:
    kb = load_knowledge()
    return kb.format_event_info_for_prompt(event_id, event_info)