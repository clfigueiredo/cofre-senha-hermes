"""Optional browser QA. Requires Playwright + Chromium, never opens a real vault.

Run from the repository with: python tests/browser_offline.py
Set QA_CHROMIUM to use an existing browser binary. All data and screenshots are temporary.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from equipment_registry.app import create_app


def main():
    with tempfile.TemporaryDirectory(prefix="equipment-offline-browser-") as directory:
        app = create_app({"DATA_DIR": Path(directory), "TESTING": True,
                          "SECRET_KEY": "temporary-browser-test-session"})
        server = make_server("127.0.0.1", 0, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    executable_path=os.environ.get("QA_CHROMIUM") or None)
                page = browser.new_page()
                # Ignore the pre-existing missing favicon; test application errors separately.
                page.route('**/favicon.ico', lambda route: route.fulfill(status=204))
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on("console", lambda message: errors.append(message.text)
                        if message.type == "error" else None)
                origin = f"http://127.0.0.1:{server.server_port}"
                page.goto(origin + '/setup')
                page.locator('[name="password"]').fill('browser-test-password-only')
                page.locator('[name="password_confirmation"]').fill('browser-test-password-only')
                page.locator('button[type="submit"]').click()
                page.get_by_role('link', name='+ Console local / offline', exact=True).click()
                for field in ['ip', 'ssh_port', 'username', 'password', 'relay_host',
                              'relay_port', 'sftp_root']:
                    assert page.locator(f'[name="{field}"]').count() == 0
                for field, value in {'name': 'Offline-QA', 'brand': 'Hyper-V',
                                     'client': 'QA Client', 'parent_host': 'QA-HOST',
                                     'console_type': 'hyper-v'}.items():
                    page.locator(f'[name="{field}"]').fill(value)
                assert page.locator('[name="network_state"]').input_value() == 'disconnected'
                artifact_dir = Path(os.environ['QA_SCREENSHOT_DIR']) if os.environ.get('QA_SCREENSHOT_DIR') else None
                if artifact_dir:
                    artifact_dir.mkdir(parents=True, exist_ok=True)
                for width in [375, 768, 1440]:
                    page.set_viewport_size({'width': width, 'height': 1000})
                    if artifact_dir:
                        page.screenshot(path=str(artifact_dir / f'offline-form-{width}.png'), full_page=True)
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                    assert page.locator('form.form-grid').evaluate('(form) => form.checkValidity()')
                    assert page.locator('[name="network_state"]').evaluate(
                        '(el) => getComputedStyle(el).fontSize') == page.locator('[name="client"]').evaluate(
                        '(el) => getComputedStyle(el).fontSize')
                page.get_by_role('button', name='Cadastrar', exact=True).click()
                assert page.get_by_text('Offline-QA', exact=True).is_visible()
                assert page.get_by_text('Rede desconectada', exact=True).is_visible()
                for width in [375, 768, 1440]:
                    page.set_viewport_size({'width': width, 'height': 1000})
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                page.get_by_role('link', name='Editar', exact=True).click()
                assert page.locator('[name="client"]').input_value() == 'QA Client'
                page.locator('[name="client"]').fill('QA Updated')
                page.get_by_role('button', name='Salvar alterações').click()
                assert app.extensions['equipment_registry'].resolve('Offline-QA').client == 'QA Updated'
                page.get_by_role('link', name='Excluir', exact=True).click()
                page.locator('[name="confirmation"]').fill('Offline-QA')
                page.locator('button[type="submit"]').last.click()
                assert app.extensions['equipment_registry'].list_equipment() == []
                assert not errors, errors
                browser.close()
                print(json.dumps({'browser': 'PASS', 'widths': [375, 768, 1440],
                                  'create_edit_delete': 'PASS', 'console_errors': errors,
                                  'data': 'temporary only'}))
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


if __name__ == '__main__':
    main()
