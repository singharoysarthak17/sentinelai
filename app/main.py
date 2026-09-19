from fastapi import FastAPI

app = FastAPI(title="SentinelAI")

@app.get("/health")
def health():
    return {"status": "ok"}