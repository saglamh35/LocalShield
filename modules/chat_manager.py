"""
Chat Manager Module - AI Chatbot Asistanı
LocalShield için interaktif AI asistan modülü
"""
import ollama
import config
from db_manager import get_all_logs
from modules.network_scanner import scan_open_ports


def get_system_summary() -> str:
    """
    Creates system summary: Latest high-risk logs and risky ports
    
    Returns:
        str: System summary text
    """
    summary_parts = []
    
    try:
        # Get last 10 high-risk logs from database
        all_logs = get_all_logs(config.DB_PATH, limit=50, order_by='DESC')
        high_risk_logs = []
        
        for log in all_logs:
            if len(log) >= 6:
                risk_level = str(log[5]).strip().lower()
                if risk_level == 'yüksek' or risk_level == 'high':
                    high_risk_logs.append(log)
            if len(high_risk_logs) >= 10:  # Maximum 10 entries
                break
        
        # Log summary
        if high_risk_logs:
            summary_parts.append("=== HIGH RISK LOGS ===\n")
            for log in high_risk_logs:
                log_id = log[0]
                timestamp = log[1]
                event_id = log[2]
                message = log[3] if len(log) > 3 and log[3] else "No message"
                ai_analysis = log[4] if len(log) > 4 and log[4] else "No analysis"
                risk_score = log[5] if len(log) > 5 else "Unknown"
                
                # Shorten message (if too long)
                message_short = message[:200] if len(message) > 200 else message
                ai_analysis_short = ai_analysis[:200] if len(ai_analysis) > 200 else ai_analysis
                
                summary_parts.append(
                    f"- Event ID {event_id} (Time: {timestamp})\n"
                    f"  Message: {message_short}\n"
                    f"  AI Analysis: {ai_analysis_short}\n"
                    f"  Risk: {risk_score}\n"
                )
        else:
            summary_parts.append("=== HIGH RISK LOGS ===\nNo high-risk logs found.\n")
        
        summary_parts.append("\n")
        
    except Exception as e:
        summary_parts.append(f"=== LOG DATA ===\nCould not read log data: {e}\n\n")
    
    try:
        # Perform port scan
        ports = scan_open_ports()
        high_risk_ports = [p for p in ports if p.get('Risk') == 'Yüksek' or p.get('Risk') == 'High']
        
        # Port summary
        if high_risk_ports:
            summary_parts.append("=== HIGH RISK OPEN PORTS ===\n")
            for port_info in high_risk_ports[:10]:  # Maximum 10 entries
                summary_parts.append(
                    f"- Port {port_info['Port']} ({port_info.get('Service', port_info.get('Servis', 'N/A'))})\n"
                    f"  PID: {port_info.get('PID', 'N/A')}\n"
                    f"  Application: {port_info.get('Application', port_info.get('Uygulama', 'Unknown'))}\n"
                    f"  Description: {port_info.get('Description', port_info.get('Açıklama', 'No description'))}\n"
                )
        else:
            summary_parts.append("=== OPEN PORTS ===\nNo high-risk open ports found.\n")
        
        # Total port statistics
        if ports:
            total_ports = len(ports)
            high_count = len(high_risk_ports)
            low_count = total_ports - high_count
            summary_parts.append(
                f"\nTotal Open Ports: {total_ports}\n"
                f"High Risk: {high_count}\n"
                f"Low Risk: {low_count}\n"
            )
        
    except Exception as e:
        summary_parts.append(f"=== PORT DATA ===\nCould not read port data: {e}\n")
    
    return "\n".join(summary_parts)


def ask_assistant(user_question: str) -> str:
    """
    Asks the AI assistant a question and gets a response based on system data
    
    Args:
        user_question: User's question
    
    Returns:
        str: AI's response
    """
    try:
        # Get system summary
        system_data = get_system_summary()
        
        # Create system prompt
        system_prompt = (
            "You are the LocalShield Cybersecurity Assistant. "
            "Your task is to answer the user's security questions based on the system data below.\n\n"
            
            "SYSTEM DATA:\n"
            f"{system_data}\n\n"
            
            "RULES:\n"
            "1. Respond in English, clearly and understandably.\n"
            "2. Base your response on the information in the system data.\n"
            "3. If there are high-risk situations, emphasize them and provide recommendations.\n"
            "4. Use user-friendly, non-technical language.\n"
            "5. If there is no relevant information in the system data, state this honestly.\n"
            "6. When providing recommendations, offer practical and actionable suggestions.\n\n"
            
            "Answer the user's question:"
        )
        
        # Ollama'ya gönder
        response = ollama.chat(
            model=config.MODEL_NAME,
            messages=[
                {
                    'role': 'system',
                    'content': system_prompt
                },
                {
                    'role': 'user',
                    'content': user_question
                }
            ]
        )
        
        # AI'ın cevabını al
        answer = response['message']['content'].strip()
        
        return answer
        
    except Exception as e:
        # Error case
        error_message = f"Sorry, an error occurred: {str(e)}\n"
        error_message += "Please try again or contact the system administrator."
        return error_message

