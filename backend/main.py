from fastapi import FastAPI
from siem_connector import get_failed_logins

app = FastAPI()

@app.get("/")
def root():
    return {"message": "SIEM Copilot API Running"}

@app.get("/failed-logins")
def failed_logins():
    results = get_failed_logins()
    return {
        "total_results": len(results),
        "events": results
    }