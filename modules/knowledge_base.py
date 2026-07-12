"""
Knowledge Base Module - Hybrid RAG system
Provides reference information about Windows Event IDs.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# File paths
BASE_DIR = Path(__file__).parent.parent
LOCAL_KNOWLEDGE_PATH = BASE_DIR / "data" / "local_knowledge.json"
EXTERNAL_KNOWLEDGE_PATH = BASE_DIR / "data" / "external_knowledge.json"


class KnowledgeBase:
    """
    Hybrid knowledge base.
    Looks up local (custom) knowledge first, then falls back to external (general) knowledge.
    """

    def __init__(self):
        """Initialize the KnowledgeBase and load the knowledge files."""
        self.local_knowledge = {}
        self.external_knowledge = {}
        self.load_knowledge()

    def load_knowledge(self):
        """Load both the local and external knowledge files."""

        # --- 1. LOAD LOCAL KNOWLEDGE ---
        try:
            if LOCAL_KNOWLEDGE_PATH.exists():
                with open(LOCAL_KNOWLEDGE_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Local knowledge is normally in the form {"4625": {...}}
                    if isinstance(data, dict):
                        self.local_knowledge = data
                    else:
                        logger.warning("⚠️ Local knowledge is not in the expected format (must be a dict).")
                logger.info(f"✅ Local knowledge loaded: {len(self.local_knowledge)} Event IDs")
            else:
                self.local_knowledge = {}
        except Exception as e:
            logger.error(f"❌ Error loading local knowledge: {e}")
            self.local_knowledge = {}

        # --- 2. LOAD EXTERNAL KNOWLEDGE ---
        try:
            if EXTERNAL_KNOWLEDGE_PATH.exists():
                with open(EXTERNAL_KNOWLEDGE_PATH, "r", encoding="utf-8") as f:
                    external_data = json.load(f)

                self.external_knowledge = {}

                # The external dataset is a JSON list (array), so we index it by Event ID
                if isinstance(external_data, list):
                    for item in external_data:
                        # Use each item's 'eventID' field as the dictionary key (e.g. "4798")
                        eid = str(item.get("eventID", "")).strip()
                        if eid:
                            self.external_knowledge[eid] = item

                    logger.info(
                        f"✅ External knowledge loaded: {len(self.external_knowledge)} Event IDs (list -> dict)"
                    )

                # If the file is already in dict form (legacy format)
                elif isinstance(external_data, dict):
                    self.external_knowledge = external_data
                    logger.info(f"✅ External knowledge loaded: {len(self.external_knowledge)} Event IDs")

            else:
                logger.warning(f"⚠️ External knowledge file not found: {EXTERNAL_KNOWLEDGE_PATH}")
                self.external_knowledge = {}

        except Exception as e:
            logger.error(f"❌ Error loading external knowledge: {e}")
            self.external_knowledge = {}

    def get_event_info(self, event_id: str) -> Optional[Dict[str, str]]:
        """
        Return knowledge for the given Event ID.
        Searches local knowledge first, then external knowledge.
        """
        # Normalize the Event ID to a clean string
        event_id_str = str(event_id).strip()

        # 1. Search LOCAL knowledge first (takes priority)
        if event_id_str in self.local_knowledge:
            info = self.local_knowledge[event_id_str].copy()
            info["source"] = "local"
            # Fill in missing fields
            if "risk_level" not in info:
                info["risk_level"] = "High"
            if "advice" not in info:
                info["advice"] = "This event has been defined as a custom rule."
            return info

        # 2. Search external knowledge (GitHub dataset)
        if event_id_str in self.external_knowledge:
            external_info = self.external_knowledge[event_id_str]
            # The external JSON structure differs, so normalize it
            info = self._normalize_external_info(external_info)
            info["source"] = "external"
            return info

        # Not found
        return None

    def _normalize_external_info(self, external_info: Any) -> Dict[str, str]:
        """
        Convert external knowledge (GitHub JSON format) into our internal format.
        """
        normalized = {"title": "", "description": "", "risk_level": "Medium", "advice": ""}

        if isinstance(external_info, dict):
            # --- TITLE ---
            # Fall back to 'subCategory' or a generic label if 'name' is missing
            normalized["title"] = (
                external_info.get("name") or external_info.get("subCategory") or f"Event {external_info.get('eventID')}"
            )

            # --- DESCRIPTION ---
            normalized["description"] = external_info.get("description", "")

            # --- RISK LEVEL ---
            # Decide based on the 'level' or 'securityMonitoringRecommandation' fields
            sec_rec = str(external_info.get("securityMonitoringRecommandation", "")).lower()
            level = str(external_info.get("level", "")).lower()

            if "yes" in sec_rec or "true" in sec_rec:
                normalized["risk_level"] = "High"
            elif "error" in level or "critical" in level:
                normalized["risk_level"] = "High"
            elif "information" in level:
                normalized["risk_level"] = "Low"

            # --- ADVICE ---
            # Prefer the explicit 'advice' field, then 'recommendation'
            if "advice" in external_info:
                normalized["advice"] = external_info["advice"]
            elif "recommendation" in external_info:
                normalized["advice"] = external_info["recommendation"]
            else:
                # Generic fallback when no advice is available
                normalized["advice"] = "Verify the source of the event and the user involved."

        return normalized


# --- Global helper functions (module-level convenience API) ---

_knowledge_base_instance = None


def load_knowledge():
    global _knowledge_base_instance
    if _knowledge_base_instance is None:
        _knowledge_base_instance = KnowledgeBase()
    return _knowledge_base_instance


def get_event_info(event_id: str) -> Optional[Dict[str, str]]:
    kb = load_knowledge()
    return kb.get_event_info(event_id)
