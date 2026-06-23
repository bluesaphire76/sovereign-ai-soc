# Pull Request

## Summary

Describe the change.

## Type of Change

- [ ] Bug fix
- [ ] Feature
- [ ] Security hardening
- [ ] Documentation
- [ ] Refactor
- [ ] Release / maintenance

## Affected Areas

- [ ] Backend API
- [ ] Frontend UI
- [ ] Authentication / users
- [ ] Incident workflow
- [ ] Case workflow
- [ ] Reports / exports
- [ ] Detection Quality
- [ ] Detection Control Plane
- [ ] AI Providers / AI Data Control
- [ ] Qdrant Semantic Memory / Recommended Playbooks
- [ ] Investigation Timeline / Graph
- [ ] Governed Remediation
- [ ] Service Operations / Operation History
- [ ] Health dashboard
- [ ] Observability / Alertmanager / Loki / Alloy
- [ ] Deployment
- [ ] Documentation
- [ ] Other

## Validation Performed

Backend:

- [ ] `.venv/bin/python -m pytest -q` passed
- [ ] tracked Python `py_compile` passed

Frontend:

- [ ] `npm run build` passed

Smoke tests:

- [ ] API health checked
- [ ] Login checked
- [ ] Main dashboard checked
- [ ] Case Queue checked
- [ ] Kanban checked
- [ ] Executive dashboard checked
- [ ] Detection Quality checked
- [ ] Health dashboard checked
- [ ] Detection Control checked
- [ ] AI provider/data policy checked
- [ ] Semantic Memory / Recommended Playbooks checked
- [ ] Operation History checked
- [ ] Report export checked

## Security Review

- [ ] No hardcoded secrets introduced
- [ ] No tokens, credentials, certificates, or private keys committed
- [ ] No stack traces or internal exception details exposed to users
- [ ] No sensitive SOC/customer data committed
- [ ] Authentication/authorization impact reviewed
- [ ] External service/data transfer impact reviewed
- [ ] AI/Qdrant/remediation decision boundaries preserved
- [ ] Documentation validators passed
- [ ] Not security relevant

## Screenshots

Add screenshots for UI changes, if useful.

## Known Limitations

List any known limitations or follow-up work.

## Checklist

- [ ] Code is focused and reviewable
- [ ] Documentation updated where needed
- [ ] Tests/builds completed
- [ ] Branch is up to date with `main`
- [ ] Ready for review
