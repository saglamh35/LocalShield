"""
LocalShield Modules
"""

from .ai_engine import Brain
from .network_scanner import scan_open_ports, get_port_summary
from .chat_manager import ask_assistant, get_system_summary
from .knowledge_base import get_event_info, load_knowledge, format_event_info_for_prompt

__all__ = [
    'Brain',
    'scan_open_ports',
    'get_port_summary',
    'ask_assistant',
    'get_system_summary',
    'get_event_info',
    'load_knowledge',
    'format_event_info_for_prompt'
]

