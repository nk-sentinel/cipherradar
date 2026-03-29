#!/bin/bash
set -e

echo "=== CipherRadar API Starting ==="

# Run migrations
echo "Running database migrations..."
python -c "
import asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

async def run_migrations():
    from app.config import settings
    engine = create_async_engine(settings.database_url)
    async with engine.begin() as conn:
        # Create tables directly from models (simpler than Alembic for dev)
        from app.db.base import Base
        import app.models  # noqa: F401 — register all models
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()
    print('Tables created successfully')

asyncio.run(run_migrations())
"

# Seed default admin user if not exists (skip if SKIP_DEFAULT_ADMIN=true)
if [ "${SKIP_DEFAULT_ADMIN:-false}" = "true" ]; then
    echo "Skipping default admin creation (SKIP_DEFAULT_ADMIN=true)"
else
echo "Checking for default admin user..."
python -c "
import asyncio
from sqlalchemy import text, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

async def seed_admin():
    from app.config import settings
    engine = create_async_engine(settings.database_url)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        # Check if admin exists
        result = await session.execute(text(\"SELECT count(*) FROM users WHERE role = 'org_admin'\"))
        count = result.scalar()
        if count and count > 0:
            print('Admin user already exists — skipping')
            return

        # Check if org exists
        org_result = await session.execute(text(\"SELECT id FROM organisations LIMIT 1\"))
        org_row = org_result.fetchone()
        if org_row:
            org_id = org_row[0]
            print(f'Using existing org: {org_id}')
        else:
            import uuid
            org_id = uuid.uuid4()
            await session.execute(text(
                \"INSERT INTO organisations (id, name, plan) VALUES (:id, :name, :plan)\"
            ), {'id': str(org_id), 'name': 'CipherRadar', 'plan': 'enterprise'})
            print(f'Created org: {org_id}')

        # Create admin user with bcrypt hash of 'admin123'
        import bcrypt as _bcrypt
        hashed = _bcrypt.hashpw(b'admin123', _bcrypt.gensalt()).decode()
        user_id = uuid.uuid4()
        await session.execute(text(
            \"INSERT INTO users (id, email, hashed_password, role, is_active, org_id) VALUES (:id, :email, :pw, :role, true, :org_id)\"
        ), {
            'id': str(user_id),
            'email': 'admin@cipherradar.local',
            'pw': hashed,
            'role': 'org_admin',
            'org_id': str(org_id),
        })
        await session.commit()
        print('Default admin created: admin@cipherradar.local / admin123')

    await engine.dispose()

asyncio.run(seed_admin())
"
fi

# Seed test data only when explicitly requested
if [ "${SEED_ON_STARTUP:-false}" = "true" ]; then
    echo "Seeding test data..."
    python scripts/seed.py
else
    echo "Skipping seed (set SEED_ON_STARTUP=true to enable)"
fi

echo "=== Starting uvicorn ==="
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
