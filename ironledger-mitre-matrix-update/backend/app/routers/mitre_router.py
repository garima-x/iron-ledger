from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import schemas
from ..database import get_db
from ..forensics import compute_mitre_hits
from ..threat_intel import MITRE_TECHNIQUES
from ..mitre_matrix import FULL_ICS_MATRIX, is_hit

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/techniques", response_model=list[schemas.MitreTechniqueOut])
def list_techniques(db: Session = Depends(get_db)):
    hits = compute_mitre_hits(db)
    return [
        schemas.MitreTechniqueOut(id=t["id"], name=t["name"], tactic=t["tactic"], hit=t["id"] in hits)
        for t in MITRE_TECHNIQUES
    ]


@router.get("/matrix")
def get_full_matrix(db: Session = Depends(get_db)):
    """The complete ATT&CK for ICS matrix (12 tactics, 79 techniques), with
    this incident's observed techniques highlighted in context — rather
    than shown as an isolated six-card list with no sense of how large the
    real framework actually is."""
    hits = compute_mitre_hits(db)
    return {
        "hit_count": len(hits),
        "total_techniques": len({tid for _, techs in FULL_ICS_MATRIX for tid, _ in techs}),
        "tactics": [
            {
                "name": tactic,
                "techniques": [
                    {"id": tid, "name": name, "hit": is_hit(tid, hits)}
                    for tid, name in techniques
                ],
            }
            for tactic, techniques in FULL_ICS_MATRIX
        ],
    }
