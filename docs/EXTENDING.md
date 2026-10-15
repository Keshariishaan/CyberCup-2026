# Extending ShieldGate (no core changes)

Restart the API after adding a plugin file; config edits made in the **Policies** page apply within ~3 s.

## Add a detector
`plugins/my_detector.py`
```python
from core.interfaces import Detector
from core.registry import register_detector
from core.types import Finding

@register_detector("my_detector")
class MyDetector(Detector):
    async def detect(self, text, ctx=None):
        return [Finding(self.name, "CONFIDENTIAL", 0, 5, "medium", message="why")] if "xyz" in text else []
```
Enable it in `config/detectors.yaml` (`my_detector: {enabled: true, settings: {...}}`), then map its finding type in `config/policy.yaml`. See `plugins/example_detector.py`.

## Add patterns, attack phrases, languages, identity rules
- Regex finding types: add an entry to `config/patterns/*.yaml` (or a new file and list it under `pattern.settings.files`).
- Injection phrases/regexes: `config/attacks/<lang>.yaml`; list the file under `injection_rules.settings.files`.
- New ID type with checksum: add a rule to `config/identity.yaml` with a `kind` from `shieldgate/detectors/validators.py` (or register your own with `@register_validator`).

## Add an action
```python
@register_action("quarantine")
class Quarantine(Action):
    blocking = True
    async def apply(self, ctx, findings): ctx.halt("blocked", "Sent to security review.")
```
Transform-style actions override `replacement(ctx, finding, value)` instead. Put the action in `policy.yaml` `rules` and in `precedence`.

## Add a role / change who sees what
Roles: Users and roles page (versioned) or `config/roles.yaml`. Row-level exceptions: **Data privileges** tab (e.g. `doc:salary_record_karan`, optional expiry).

## Add an LLM provider, vector store, embedder, report, skill
Subclass the interface, decorate with `@register_llm|vector_store|embedder|report|skill`, select by name (`LLM_PROVIDER`, `VECTOR_STORE`, `EMBEDDER`, `?format=`, `roles.yaml skills`). Skills receive only the sanitized query and must enforce their own data access (see `salary_analysis`).

## Add a pipeline stage
`@register_stage("my_stage")` with `async run(ctx)`; call `ctx.halt(status, message)` to stop; list it in `config/pipeline.yaml`. Set `always_run = True` for bookkeeping stages.

## Add a screen
Add the name to `screens` and to roles in `roles.yaml`, create `frontend/pages/N_Name.py` starting with `guard("name")`, register it in `SCREEN_PAGES` (`frontend/app.py`), and protect its routes with `Depends(require_screen("name"))`.

## Database changes
Edit `shieldgate/db/models.py`, then `alembic revision --autogenerate -m "..."` and `alembic upgrade head`.
