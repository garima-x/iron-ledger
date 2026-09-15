from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import Base, engine
from .config import settings
from .blockchain import chain_status
from .routers import ledger, telemetry, forensics_router, mitre_router, reports_router, simulate_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="IronLedger API",
    description="Blockchain-anchored digital forensics & threat intelligence framework for ICS incident response.",
    version="0.1.0",
)

origins = ["*"] if settings.cors_origins.strip() == "*" else [o.strip() for o in settings.cors_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ledger.router)
app.include_router(telemetry.router)
app.include_router(forensics_router.router)
app.include_router(mitre_router.router)
app.include_router(reports_router.router)
app.include_router(simulate_router.router)


@app.get("/")
def root():
    return {
        "service": "IronLedger API",
        "chain": chain_status(),
    }
