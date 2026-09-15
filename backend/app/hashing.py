import hashlib
import json


def compute_hash(source: str, command: str, entity: str, params: dict, prev_hash: str) -> tuple[str, str]:
    """Returns (preimage_string, sha256_hex). Mirrors the frontend's
    H(source, command, entity, params, prevHash) construction so the same
    tamper-detection logic — recompute and compare — holds on both sides."""
    params_str = json.dumps(params, sort_keys=True, separators=(",", ":"))
    preimage = f"{source}|{command}|{entity}|{params_str}|{prev_hash}"
    digest = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
    return preimage, digest


GENESIS_HASH = "0" * 64
