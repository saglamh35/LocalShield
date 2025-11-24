import ollama

print("LocalShield Beyni test ediliyor...")

# Yapay zekaya basit bir soru soruyoruz
response = ollama.chat(model='gemma3:4b', messages=[
  {
    'role': 'user',
    'content': 'Bana siber güvenlik uzmanı gibi kısa, tek cümlelik havalı bir selamlama yap.',
  },
])

# Cevabı ekrana yazdırıyoruz
print("\n--- YZ Cevabı ---")
print(response['message']['content'])
print("-----------------")