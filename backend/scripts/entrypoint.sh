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

# Seed default admin user if not exists
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
        result = await session.execute(text(\"SELECT id FROM users WHERE email = 'admin@cipherradar.local'\"))
        if result.fetchone():
            print('Admin user already exists')
            return

        # Create org
        import uuid
        org_id = uuid.uuid4()
        await session.execute(text(
            \"INSERT INTO organisations (id, name, plan) VALUES (:id, :name, :plan)\"
        ), {'id': str(org_id), 'name': 'Default', 'plan': 'enterprise'})

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

echo "=== Starting uvicorn ==="
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
