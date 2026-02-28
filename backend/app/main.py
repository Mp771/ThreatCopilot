from fastapi import FastAPI
from app.routes import logs, nlp
from fastapi.middleware.cors import CORSMiddleware
from app.routes import report

app = FastAPI(title="ThreatCopilot API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Include route modules
app.include_router(logs.router)
app.include_router(nlp.router)
app.include_router(report.router)


@app.get("/")
def root():
    return {"message": "ThreatCopilot API Running"}