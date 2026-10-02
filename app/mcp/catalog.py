"""mcp-catalog — threat_pack, model_adversarial, mm_controls, playbooks."""

from __future__ import annotations

from typing import Any

from .. import threatpack as tp
from .. import model_eval as me
from .. import leakage as lk


def threat_pack() -> dict[str, Any]:
    return tp.pack_manifest()


def model_adversarial() -> dict[str, Any]:
    return {"id": me.MODEL_ADV_ID, "version": me.MODEL_ADV_VERSION, "classes": me.ATTACK_CLASSES, "fingerprint": me.model_adv_fingerprint()}


def mm_controls() -> list[dict[str, Any]]:
    return me.MITIGATION_CATALOG


def playbooks() -> list[dict[str, Any]]:
    return lk.PLAYBOOKS
