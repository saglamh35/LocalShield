"""Ad-hoc smoke test: check that the local Ollama "brain" is reachable and
responding. The pytest suite mocks Ollama, so this standalone script is the
quick manual way to confirm the local LLM actually answers."""

import ollama

print("Testing the LocalShield brain...")

# Ask the AI a simple question
response = ollama.chat(model='gemma3:4b', messages=[
  {
    'role': 'user',
    'content': 'Give me a short, one-sentence cool greeting as if you were a cybersecurity expert.',
  },
])

# Print the response to the screen
print("\n--- AI Response ---")
print(response['message']['content'])
print("-------------------")
