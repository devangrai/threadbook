#!/usr/bin/env python3
"""Dispatch run-scoped requirement evaluators."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.evaluators import (  # noqa: E402
    p00_gmail,
    p00_jobs,
    p00_openai,
    p00_package,
    p00_photos,
    p00_segmentation,
    p01_foundation,
    p02_manual_catalog,
    p03_receipt_images,
    p03_receipts,
    p04_photo_analysis,
    p05_reconciliation,
    p06_connectors,
    p06_google_photos,
    p06_photokit,
    p07_outfits,
    p07_recommendations,
    p08_try_on,
    p09_backup,
    p09_deletion,
    p09_diagnostics,
    p09_supply_chain,
    p09_update,
)


def main() -> int:
    run_dir_value = os.environ.get("HARNESS_RUN_DIR")
    evidence_dir_value = os.environ.get("HARNESS_EVIDENCE_DIR")
    if not run_dir_value or not evidence_dir_value:
        print("HARNESS_RUN_DIR and HARNESS_EVIDENCE_DIR are required", file=sys.stderr)
        return 2

    run_dir = Path(run_dir_value)
    evidence_dir = Path(evidence_dir_value)
    snapshot = json.loads((run_dir / "requirements.json").read_text(encoding="utf-8"))
    selected = set(snapshot["selected_requirement_ids"])

    package_requirements = {"P00-PKG-002", "P00-GAT-001"}
    job_requirements = {"P00-JOB-001"}
    gmail_requirements = {"P00-GML-001"}
    openai_requirements = {"P00-AI-001", "P00-PRV-001"}
    photos_requirements = {"P00-PHO-001"}
    segmentation_requirements = {"P00-SEG-001"}
    foundation_requirements = set(p01_foundation.REQUIREMENT_IDS)
    manual_catalog_requirements = set(p02_manual_catalog.REQUIREMENT_IDS)
    receipt_requirements = set(p03_receipts.REQUIREMENT_IDS)
    receipt_image_requirements = set(p03_receipt_images.REQUIREMENT_IDS)
    photo_analysis_requirements = set(p04_photo_analysis.REQUIREMENT_IDS)
    reconciliation_requirements = set(p05_reconciliation.REQUIREMENT_IDS)
    connector_requirements = set(p06_connectors.REQUIREMENT_IDS)
    google_photos_requirements = set(p06_google_photos.REQUIREMENT_IDS)
    photokit_requirements = set(p06_photokit.REQUIREMENT_IDS)
    outfit_requirements = set(p07_outfits.REQUIREMENT_IDS)
    recommendation_requirements = set(p07_recommendations.REQUIREMENT_IDS)
    try_on_requirements = set(p08_try_on.REQUIREMENT_IDS)
    backup_requirements = set(p09_backup.REQUIREMENT_IDS)
    deletion_requirements = set(p09_deletion.REQUIREMENT_IDS)
    diagnostics_requirements = set(p09_diagnostics.REQUIREMENT_IDS)
    supply_chain_requirements = set(p09_supply_chain.REQUIREMENT_IDS)
    update_requirements = set(p09_update.REQUIREMENT_IDS)
    supported = (
        package_requirements
        | job_requirements
        | gmail_requirements
        | openai_requirements
        | photos_requirements
        | segmentation_requirements
        | foundation_requirements
        | manual_catalog_requirements
        | receipt_requirements
        | receipt_image_requirements
        | photo_analysis_requirements
        | reconciliation_requirements
        | connector_requirements
        | google_photos_requirements
        | photokit_requirements
        | outfit_requirements
        | recommendation_requirements
        | try_on_requirements
        | backup_requirements
        | deletion_requirements
        | diagnostics_requirements
        | supply_chain_requirements
        | update_requirements
    )
    requested = selected & supported
    unsupported = selected - supported
    if unsupported:
        print(
            "No evaluator registered for: " + ", ".join(sorted(unsupported)),
            file=sys.stderr,
        )
        return 1
    exit_code = 0
    package_requested = requested & package_requirements
    if package_requested:
        exit_code = max(
            exit_code,
            p00_package.evaluate(ROOT, evidence_dir, package_requested),
        )
    job_requested = requested & job_requirements
    if job_requested:
        exit_code = max(
            exit_code,
            p00_jobs.evaluate(ROOT, evidence_dir, job_requested),
        )
    gmail_requested = requested & gmail_requirements
    if gmail_requested:
        exit_code = max(
            exit_code,
            p00_gmail.evaluate(ROOT, evidence_dir, gmail_requested),
        )
    openai_requested = requested & openai_requirements
    if openai_requested:
        exit_code = max(
            exit_code,
            p00_openai.evaluate(ROOT, evidence_dir, openai_requested),
        )
    photos_requested = requested & photos_requirements
    if photos_requested:
        exit_code = max(
            exit_code,
            p00_photos.evaluate(ROOT, evidence_dir, photos_requested),
        )
    segmentation_requested = requested & segmentation_requirements
    if segmentation_requested:
        exit_code = max(
            exit_code,
            p00_segmentation.evaluate(
                ROOT,
                evidence_dir,
                segmentation_requested,
            ),
        )
    foundation_requested = requested & foundation_requirements
    if foundation_requested:
        exit_code = max(
            exit_code,
            p01_foundation.evaluate(
                ROOT,
                evidence_dir,
                foundation_requested,
            ),
        )
    manual_catalog_requested = requested & manual_catalog_requirements
    if manual_catalog_requested:
        exit_code = max(
            exit_code,
            p02_manual_catalog.evaluate(
                ROOT,
                evidence_dir,
                manual_catalog_requested,
            ),
        )
    receipt_requested = requested & receipt_requirements
    if receipt_requested:
        exit_code = max(
            exit_code,
            p03_receipts.evaluate(
                ROOT,
                evidence_dir,
                receipt_requested,
            ),
        )
    receipt_image_requested = requested & receipt_image_requirements
    if receipt_image_requested:
        exit_code = max(
            exit_code,
            p03_receipt_images.evaluate(
                ROOT,
                evidence_dir,
                receipt_image_requested,
            ),
        )
    photo_analysis_requested = requested & photo_analysis_requirements
    if photo_analysis_requested:
        exit_code = max(
            exit_code,
            p04_photo_analysis.evaluate(
                ROOT,
                evidence_dir,
                photo_analysis_requested,
            ),
        )
    reconciliation_requested = requested & reconciliation_requirements
    if reconciliation_requested:
        exit_code = max(
            exit_code,
            p05_reconciliation.evaluate(
                ROOT,
                evidence_dir,
                reconciliation_requested,
            ),
        )
    connector_requested = requested & connector_requirements
    if connector_requested:
        exit_code = max(
            exit_code,
            p06_connectors.evaluate(
                ROOT,
                evidence_dir,
                connector_requested,
            ),
        )
    google_photos_requested = requested & google_photos_requirements
    if google_photos_requested:
        exit_code = max(
            exit_code,
            p06_google_photos.evaluate(
                ROOT,
                evidence_dir,
                google_photos_requested,
            ),
        )
    photokit_requested = requested & photokit_requirements
    if photokit_requested:
        exit_code = max(
            exit_code,
            p06_photokit.evaluate(
                ROOT,
                evidence_dir,
                photokit_requested,
            ),
        )
    outfit_requested = requested & outfit_requirements
    if outfit_requested:
        exit_code = max(
            exit_code,
            p07_outfits.evaluate(
                ROOT,
                evidence_dir,
                outfit_requested,
            ),
        )
    recommendation_requested = requested & recommendation_requirements
    if recommendation_requested:
        exit_code = max(
            exit_code,
            p07_recommendations.evaluate(
                ROOT,
                evidence_dir,
                recommendation_requested,
            ),
        )
    try_on_requested = requested & try_on_requirements
    if try_on_requested:
        exit_code = max(
            exit_code,
            p08_try_on.evaluate(
                ROOT,
                evidence_dir,
                try_on_requested,
            ),
        )
    backup_requested = requested & backup_requirements
    if backup_requested:
        exit_code = max(
            exit_code,
            p09_backup.evaluate(
                ROOT,
                evidence_dir,
                backup_requested,
            ),
        )
    deletion_requested = requested & deletion_requirements
    if deletion_requested & p09_deletion.TRIGGER_REQUIREMENT_IDS:
        exit_code = max(
            exit_code,
            p09_deletion.evaluate(
                ROOT,
                evidence_dir,
                deletion_requested,
            ),
        )
    diagnostics_requested = requested & diagnostics_requirements
    if diagnostics_requested & p09_diagnostics.TRIGGER_REQUIREMENT_IDS:
        exit_code = max(
            exit_code,
            p09_diagnostics.evaluate(
                ROOT,
                evidence_dir,
                diagnostics_requested,
            ),
        )
    supply_chain_requested = requested & supply_chain_requirements
    if supply_chain_requested & p09_supply_chain.TRIGGER_REQUIREMENT_IDS:
        exit_code = max(
            exit_code,
            p09_supply_chain.evaluate(
                ROOT,
                evidence_dir,
                supply_chain_requested,
            ),
        )
    update_requested = requested & update_requirements
    if update_requested & p09_update.TRIGGER_REQUIREMENT_IDS:
        exit_code = max(
            exit_code,
            p09_update.evaluate(
                ROOT,
                evidence_dir,
                update_requested,
            ),
        )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
