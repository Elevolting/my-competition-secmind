import pytest

from security_agent.api import build_runtime
from security_agent.schemas import AttachmentRef, TaskRequest
from security_agent.target_urls import normalize_target_url


@pytest.mark.parametrize('value', [
    'https://target.test/https://outside.test/',
    'https://target.test/http%3A%2F%2Foutside.test/',
    'ftp://target.test/', 'https://user:pass@target.test/',
    'http://target.test:invalid/', 'https://target.test/#fragment',
    'https://bad host/', 'https://target.test/%ZZ',
    'https://target.test/https%253A%252F%252Foutside.test/',
])
def test_rejects_invalid_authorization_urls(value):
    with pytest.raises(ValueError):
        normalize_target_url(value)


@pytest.mark.asyncio
async def test_uploaded_url_must_match_authorized_scope(settings):
    settings.prepare_directories()
    material = settings.upload_root / 'target.url'
    material.write_text('https://target.test/actual', encoding='utf-8')
    service, _, gateway, _ = build_runtime(settings)
    try:
        task = TaskRequest(objective='Inspect target', target_scope=['https://target.test/other'],
                           attachments=[AttachmentRef(ref=str(material), name='target.url')])
        with pytest.raises(ValueError, match='不一致'):
            service.submit(task)
        task.target_scope = ['https://target.test/actual']
        assert service.submit(task)
    finally:
        await service.shutdown()
        await gateway.close()


@pytest.mark.asyncio
async def test_url_material_symlink_is_rejected(settings):
    settings.prepare_directories()
    material = settings.upload_root / 'real.url'
    material.write_text('https://target.test/', encoding='utf-8')
    linked = settings.upload_root / 'link.url'
    try:
        linked.symlink_to(material)
    except (OSError, NotImplementedError):
        pytest.skip('Symlinks unavailable')
    service, _, gateway, _ = build_runtime(settings)
    try:
        task = TaskRequest(objective='Inspect target', target_scope=['https://target.test/'],
                           attachments=[AttachmentRef(ref=str(linked), name='link.url')])
        with pytest.raises(ValueError):
            service.submit(task)
    finally:
        await service.shutdown()
        await gateway.close()
