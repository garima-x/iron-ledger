from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import schemas
from ..database import get_db
from ..forensics import compute_mitre_hits
from ..threat_intel import MITRE_TECHNIQUES

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/techniques", response_model=list[schemas.MitreTechniqueOut])
def list_techniques(db: Session = Depends(get_db)):
    hits = compute_mitre_hits(db)
    return [
        schemas.MitreTechniqueOut(id=t["id"], name=t["name"], tactic=t["tactic"], hit=t["id"] in hits)
        for t in MITRE_TECHNIQUES
    ]
