# Plan 3 Pattern Reference: Scan Lifecycle Implementation Patterns

Use this as a reference when implementing Plan 3 (Scan Lifecycle) tasks. Extends plan2-patterns.md — read that first for base route/service/test/RBAC patterns.

## WebSocket Endpoint Pattern (Backend)

Follow the existing pattern in `backend/app/api/v1/ws.py`:

```python
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.cache_service import get_redis

router = APIRouter(tags=["websocket"])

@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str) -> None:
    await websocket.accept()
    redis = get_redis()
    pubsub = redis.pubsub()
    channel = f"scan:{scan_id}"
    await pubsub.subscribe(channel)
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                await websocket.send_text(message["data"])
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.close()
```

## Publishing Scan Progress (Backend Service)

```python
import json
from app.services.cache_service import get_redis

async def publish_progress(scan_id: str, status: str, progress_pct: int, detail: str = "") -> None:
    redis = get_redis()
    payload = json.dumps({
        "scan_id": scan_id,
        "status": status,
        "progress_pct": progress_pct,
        "detail": detail,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    await redis.publish(f"scan:{scan_id}", payload)
```

**Progress stages and percentages:**
```python
SCAN_STAGES = {
    "queued": 0,
    "cloning": 10,
    "scanning_pass1": 30,
    "scanning_pass2": 60,
    "generating_cbom": 85,
    "completed": 100,
    "failed": -1,
}
```

## Testing WebSocket with fakeredis (Backend)

```python
import fakeredis.aioredis
from unittest.mock import patch, AsyncMock

@pytest.mark.asyncio
async def test_publish_progress():
    fake_redis = fakeredis.aioredis.FakeRedis()
    pubsub = fake_redis.pubsub()
    await pubsub.subscribe("scan:test-123")

    with patch("app.services.scan_progress_service.get_redis", return_value=fake_redis):
        await publish_progress("test-123", "cloning", 10)

    message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
    assert message is not None
    data = json.loads(message["data"])
    assert data["status"] == "cloning"
    assert data["progress_pct"] == 10
```

## Cron Expression Handling (Backend)

Use `croniter` for validation and next-run calculation:

```python
from croniter import croniter
from datetime import datetime, timezone

def validate_cron(expression: str) -> bool:
    return croniter.is_valid(expression)

def next_run(expression: str, tz: str = "UTC") -> datetime:
    base = datetime.now(timezone.utc)
    cron = croniter(expression, base)
    return cron.get_next(datetime)

# Preset conversion
PRESETS = {
    "daily": "0 {hour} * * *",
    "weekly": "0 {hour} * * 0",  # Sunday
}
```

## Cascade Config Resolution Pattern

Same pattern as D18 Jira and D26 Policy — project → group → org → none:

```python
async def resolve_schedule(project_id: uuid.UUID, session: AsyncSession) -> ScheduleInfo:
    # 1. Check project schedule
    project = await _get_project(project_id, session)
    if project.schedule_cron:
        return ScheduleInfo(cron=project.schedule_cron, tz=project.schedule_timezone, source="project")

    # 2. Check group schedule
    group = await _get_group(project.group_id, session)
    if group and group.schedule_cron:
        return ScheduleInfo(cron=group.schedule_cron, tz=group.schedule_timezone, source="group")

    # 3. Check org default
    org = await _get_org(project.org_id, session)
    if org.default_schedule_cron:
        return ScheduleInfo(cron=org.default_schedule_cron, tz=org.default_schedule_timezone, source="org")

    return ScheduleInfo(cron=None, tz="UTC", source="none")
```

## Frontend WebSocket Hook Pattern

Using `mock-socket` for testing:

```typescript
// src/lib/use-scan-progress.ts
import { useState, useEffect, useRef } from 'react';

interface ScanProgress {
  status: string;
  progressPct: number;
  detail: string;
  isComplete: boolean;
  isError: boolean;
}

export function useScanProgress(scanId: string | null): ScanProgress {
  const [progress, setProgress] = useState<ScanProgress>({
    status: 'queued', progressPct: 0, detail: '', isComplete: false, isError: false,
  });
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!scanId) return;
    const ws = new WebSocket(`ws://${window.location.host}/api/v1/ws/scans/${scanId}`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setProgress({
        status: data.status,
        progressPct: data.progress_pct,
        detail: data.detail ?? '',
        isComplete: data.status === 'completed',
        isError: data.status === 'failed',
      });
    };

    return () => { ws.close(); wsRef.current = null; };
  }, [scanId]);

  return progress;
}
```

**Testing with mock-socket:**
```typescript
import { Server } from 'mock-socket';

const fakeURL = 'ws://localhost/api/v1/ws/scans/test-123';
const mockServer = new Server(fakeURL);

mockServer.on('connection', (socket) => {
  socket.send(JSON.stringify({ status: 'cloning', progress_pct: 10 }));
});

// Then render component using useScanProgress('test-123')
// Assert that progress bar shows 10%

afterEach(() => mockServer.close());
```

## Scan Modal — Context-Aware Behavior

```typescript
interface ScanModalProps {
  context: 'dashboard' | 'project-row' | 'project-overview';
  projectId?: string;         // pre-filled when context != 'dashboard'
  defaultSourceType?: string; // 'repository' | 'container' | 'artifact'
}
```

| Context | Behavior |
|---|---|
| `dashboard` | Full 3-tab modal, project selector first |
| `project-row` | Pre-fill project, show source tab |
| `project-overview` | Simplified (branch + policy), "More options" expands to full |

## Artifact Registry — Auth Config Schema

```typescript
interface RegistryAuthConfig {
  type: 'token' | 'userpass' | 'iam_role' | 'service_account';
  token?: string;
  username?: string;
  password?: string;
  role_arn?: string;           // AWS IAM
  service_account_json?: string; // GCP
}
```

Registry types: `jfrog | ecr | gcr | acr | docker_hub | harbor | gitlab | custom`

## MSW Handler Updates

Every new endpoint gets a handler. For WebSocket, MSW doesn't support WS — frontend tests use `mock-socket` instead.

```typescript
// Scan queue
http.get('/api/v1/scans', ({ request }) => {
  const url = new URL(request.url);
  const status = url.searchParams.get('status');
  // filter mock scans by status
  return HttpResponse.json({ items: [...], total: N, page: 1, perPage: 25 });
}),

// Scan schedule
http.get('/api/v1/projects/:projectId/schedule', () =>
  HttpResponse.json({ cron: '0 2 * * *', timezone: 'UTC', source: 'project', nextRun: '...' })
),

// Registries
http.get('/api/v1/admin/registries', () =>
  HttpResponse.json([{ id: '...', name: 'JFrog', registryType: 'jfrog', url: '...', status: 'active' }])
),
```

## Doc Update Checklist (per task)

- [ ] RBAC-REFERENCE.md — add endpoint role matrix
- [ ] MSW handlers — add mock for new endpoint (except WebSocket — use mock-socket)
- [ ] UX-AUDIT-FINDINGS.md — mark #36-40 as DONE when shipped
