"""Database seeding script (placeholder).

Usage:
    python -m scripts.seed

This will be implemented when the first endpoints that require
seed data are built.
"""


async def seed_database() -> None:
    """Seed the database with initial development data."""
    # TODO: implement seeding for organisations, projects, and sample scans
    pass


if __name__ == "__main__":
    import asyncio

    asyncio.run(seed_database())
