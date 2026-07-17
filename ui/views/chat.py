"""AI Assistant tab: local-LLM chat grounded in log and port data."""

import time

import streamlit as st

from modules.chat_manager import ask_assistant


def stream_data(text):
    """Generator function for typewriter effect"""
    words = text.split(" ")
    for word in words:
        yield word + " "
        time.sleep(0.02)  # Small delay between words


def render() -> None:
    st.header("💬 Cybersecurity Assistant")
    st.caption("You can ask questions about your system. AI will respond based on log and port data.")

    # Initialize Session State
    if "messages" not in st.session_state:
        st.session_state.messages = []
        # Initial welcome message
        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": "Hello! I'm the LocalShield Cybersecurity Assistant. "
                "You can ask questions about your system. "
                "For example: 'Are there any risks in my system?', 'Which ports are open?', 'What are the latest security events?'",
            }
        )

    # Display Message History (in bubbles)
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # New Message Input
    if prompt := st.chat_input("What would you like to know about your system's status?"):
        # Add and show user message
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Ask Assistant
        with st.chat_message("assistant"):
            with st.spinner("Analyzing data..."):
                try:
                    response = ask_assistant(prompt)
                    # Use typewriter effect
                    st.write_stream(stream_data(response))
                    st.session_state.messages.append({"role": "assistant", "content": response})
                except Exception as e:
                    error_msg = f"Sorry, an error occurred: {str(e)}"
                    st.error(error_msg)
                    st.session_state.messages.append({"role": "assistant", "content": error_msg})

    # Clear chat history button
    if st.session_state.messages and len(st.session_state.messages) > 1:
        st.markdown("---")
        col_clear1, col_clear2, col_clear3 = st.columns([1, 1, 1])
        with col_clear2:
            if st.button("🗑️ Clear Chat History", use_container_width=True):
                st.session_state.messages = []
                st.rerun()
