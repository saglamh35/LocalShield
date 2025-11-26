"""
AI Engine Module - Brain Class for Windows Log Analysis
Production-Ready: Updated with JSON output format and type hints
"""
import ollama
import re
import json
import logging
from typing import Optional, Dict, Any, Tuple
from pydantic import ValidationError

import config
from modules.knowledge_base import get_event_info
from modules.ai_models import AIAnalysisResponse

# Logging yapılandırması
logger = logging.getLogger(__name__)


class Brain:
    """
    AI class that analyzes Windows security logs.
    Uses local LLM running on Ollama.
    Production-Ready: JSON output format and type-safe parsing
    """
    
    def __init__(self, model_name: Optional[str] = None) -> None:
        """
        Initializes Brain class.
        
        Args:
            model_name: Ollama model name (default: from config.py)
        """
        self.model_name: str = model_name or config.MODEL_NAME
        
        # System prompt for JSON output format
        self.system_prompt: str = """You are a Senior SOC Analyst (Cyber Security Expert).
Analyze the Windows Log provided to you and respond in the following JSON format:

{
    "risk_score": "Low" or "Medium" or "High",
    "user_entity": "Detected username or machine name",
    "summary": "Non-technical, clear English explanation of the event",
    "advice": "What should be done in this case? Practical recommendations",
    "event_id_explanation": "Educational explanation about Event ID (optional)"
}

IMPORTANT: 
- Your response must be ONLY JSON, no other text
- JSON must be valid and parseable
- Be brief, clear, and professional"""
    
    def extract_event_id(self, log_text: str) -> Optional[str]:
        """
        Extracts Event ID from log text.
        
        Args:
            log_text: Log text
        
        Returns:
            Event ID (string) or None
        """
        match = re.search(r'Event ID\s*[:#]?\s*(\d+)', log_text, re.IGNORECASE)
        return match.group(1) if match else None
    
    def analyze(self, log_text: str) -> Tuple[str, str]:
        """
        Analyzes Windows log text and returns response in JSON format.
        Improves analysis quality by retrieving information from knowledge base (Hybrid RAG).
        
        Args:
            log_text: Windows log text to analyze
        
        Returns:
            tuple[str, str]: (markdown_analysis, risk_score) - Markdown and risk level for Dashboard
        """
        try:
            # Try to extract Event ID from log text
            event_id: Optional[str] = self.extract_event_id(log_text)
            
            # Retrieve information from knowledge base (RAG)
            kb_info: Optional[Dict[str, Any]] = None
            if event_id:
                try:
                    kb_info = get_event_info(event_id)
                    if kb_info:
                        logger.info(f"Knowledge base information found (Event ID: {event_id}, Source: {kb_info.get('source', 'unknown')})")
                except Exception as e:
                    logger.warning(f"Knowledge base error: {e}")
            
            # Prepare system prompt
            enhanced_prompt = self.system_prompt
            
            # Add RAG information to prompt (if exists) - PROMPT HARDENING
            if kb_info:
                extra_instruction = f"""

[🛑 SPECIAL INSTRUCTION - CRITICAL SECURITY PROTOCOL]:
There is a SECURITY PROTOCOL defined for this event (ID: {event_id}).

In the JSON output's "advice" field, paste the following text VERBATIM. Do not create your own sentences.

MANDATORY TEXT: "{kb_info.get('advice', '')}"

Also write this in the "risk_score" field: "{kb_info.get('risk_level', 'Medium')}"

[IMPORTANT]: Do not modify the "MANDATORY TEXT" above, copy-paste it.
"""
                enhanced_prompt += extra_instruction
            
            # Send to AI
            logger.debug(f"Starting AI analysis (Event ID: {event_id})")
            response = ollama.chat(
                model=self.model_name,
                messages=[
                    {
                        'role': 'system',
                        'content': enhanced_prompt
                    },
                    {
                        'role': 'user',
                        'content': f"Analyze this Windows security log:\n\n{log_text}"
                    }
                ]
            )
            
            # Get AI's response
            raw_response: str = response['message']['content'].strip()
            
            # Parse JSON
            try:
                # Clean JSON (if in markdown code block)
                json_str = raw_response
                if "```json" in json_str:
                    json_str = json_str.split("```json")[1].split("```")[0].strip()
                elif "```" in json_str:
                    json_str = json_str.split("```")[1].split("```")[0].strip()
                
                # Parse JSON
                json_data = json.loads(json_str)
                
                # Validate with Pydantic model
                analysis_response = AIAnalysisResponse(**json_data)
                
                logger.info(f"AI analysis successfully parsed (Risk: {analysis_response.risk_score})")
                
                # Convert to markdown format and return with risk_score
                markdown_analysis = analysis_response.to_markdown()
                return markdown_analysis, analysis_response.risk_score
                
            except (json.JSONDecodeError, ValidationError) as e:
                logger.error(f"JSON parse error: {e}, Raw response: {raw_response[:200]}")
                # Fallback: Return raw response
                fallback_markdown = self._create_fallback_response(event_id, raw_response)
                return fallback_markdown, "Medium"
                
        except Exception as e:
            logger.error(f"AI analysis error: {e}", exc_info=True)
            fallback_markdown = self._create_fallback_response(event_id, f"AI Error: {str(e)}")
            return fallback_markdown, "Medium"
    
    def _create_fallback_response(self, event_id: Optional[str], error_message: str) -> str:
        """
        Creates fallback response in error cases.
        
        Args:
            event_id: Event ID (if exists)
            error_message: Error message
        
        Returns:
            str: Fallback markdown response
        """
        event_id_str = event_id if event_id else "Unknown"
        return f"""🆔 What is Event ID {event_id_str}?
This Event ID is an event recorded by the Windows security system.

🕵️‍♂️ Event Analysis
User: Could Not Be Analyzed
Status: {error_message}
Risk: Medium

💡 Recommendation
Check the log message manually or contact the system administrator."""
