## What changed and why

<!-- Describe the change and the problem it solves. Link the issue it
closes or the discussion that prompted it, e.g. "Closes #123". -->

## How this was tested

<!-- Which of backend pytest / frontend npm test / mcp-server pytest did
you run, and what did you check by hand (if anything)? -->

## Checklist

- [ ] I ran the relevant checks locally (see [CONTRIBUTING.md](../CONTRIBUTING.md#running-the-checks-locally)) and they pass
- [ ] I added or updated tests covering this change
- [ ] I updated `ARCHITECTURE.md` / a component README if this changes how the system is put together
- [ ] I did not commit real credentials, tokens, or API keys (test fixtures use obviously-fake values)
- [ ] If this touches the schema (`backend/app/models/models.py`), I generated and reviewed an Alembic migration
