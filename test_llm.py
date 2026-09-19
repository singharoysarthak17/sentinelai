import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

def ping(name, base_url, key_var, model_var):
    client = OpenAI(base_url=base_url, api_key=os.environ[key_var])
    r = client.chat.completions.create(
        model=os.environ[model_var],
        messages=[{"role": "user", "content": "Reply with the single word: ready"}],
        max_tokens=200,
    )
    print(name, "->", r.choices[0].message.content)

ping("gemini", "https://generativelanguage.googleapis.com/v1beta/openai/", "GEMINI_API_KEY", "GEMINI_MODEL")
ping("groq", "https://api.groq.com/openai/v1", "GROQ_API_KEY", "GROQ_MODEL")