"""
Seed TestDefinition records from test_catalog.yaml into the DB.
Usage: python3 test_catalog_seeder.py
"""
import asyncio
import logging
from pathlib import Path

import yaml

from asserters import ASSERTERS
from database import AsyncSessionLocal, init_db
from db_repository import TestDefinitionRepository

log = logging.getLogger(__name__)
CATALOG_FILE = Path(__file__).parent / "test_catalog.yaml"


async def _seed() -> None:
    await init_db()
    catalog = yaml.safe_load(CATALOG_FILE.read_text())
    if not catalog:
        log.warning("Empty catalog, nothing to seed.")
        return

    seeded = created = updated = 0
    async with AsyncSessionLocal() as session:
        td_repo = TestDefinitionRepository(session)

        for entry in catalog:
            key = entry["key"]
            assertion_type = entry["assertion_type"]

            if assertion_type not in ASSERTERS:
                raise ValueError(
                    f"Unknown assertion_type '{assertion_type}' for key '{key}'. "
                    f"Available: {sorted(ASSERTERS)}"
                )

            obj, was_created = await td_repo.upsert(
                key=key,
                title=entry.get("title", key),
                description=entry.get("description"),
                producer=entry["producer"],
                assertion_type=assertion_type,
                params=entry.get("params", {}),
                severity=entry.get("severity", "MEDIUM"),
                default_remediation=entry.get("remediation"),
                frequency_minutes=entry.get("frequency_minutes", 1440),
                enabled=True,
            )
            seeded += 1
            if was_created:
                created += 1
                log.info("created: %s", key)
            else:
                updated += 1
                log.info("updated: %s", key)

        await session.commit()

    log.info("Seeded %d test definitions: %d created, %d updated.", seeded, created, updated)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    asyncio.run(_seed())


if __name__ == "__main__":
    main()
