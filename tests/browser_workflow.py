#!/usr/bin/env python3
"""Local browser/MCP acceptance helper; browser and test account paths are explicit."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import time
import traceback
import urllib.parse
from playwright.sync_api import sync_playwright

parser = argparse.ArgumentParser()
parser.add_argument('--browser', required=True)
parser.add_argument('--credentials', required=True)
parser.add_argument('--report', required=True)
parser.add_argument('--previous-report')
args = parser.parse_args()
ROOT = Path(args.report).parent
BASE = 'http://127.0.0.1:3098'  # Synthetic isolated-test fixture.
report = {'passed': False, 'checks': {}, 'browser_external_requests': [], 'browser_errors': []}
report['console_errors'] = []
report['failed_requests'] = []

def main():
    credentials = json.loads(Path(args.credentials).read_text())
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=args.browser,
            headless=True, args=['--no-sandbox', '--disable-background-networking',
                '--disable-component-update', '--disable-domain-reliability',
                '--disable-sync', '--metrics-recording-only', '--no-first-run'])
        context = browser.new_context(viewport={'width': 1440, 'height': 1000})
        page = context.new_page()
        def request_seen(request):
            parsed = urllib.parse.urlsplit(request.url)
            if parsed.scheme in ['http', 'https', 'ws', 'wss'] and parsed.netloc != '127.0.0.1:3098':
                report['browser_external_requests'].append(request.url.split('?', 1)[0])
        context.on('request', request_seen)
        page.on('pageerror', lambda error: report['browser_errors'].append(str(error)))
        page.on('console', lambda message: report['console_errors'].append(message.text[:400])
                if message.type in ['warning', 'error'] and len(report['console_errors']) < 30 else None)
        page.on('requestfailed', lambda request: report['failed_requests'].append(
            {'url': request.url.split('?', 1)[0], 'failure': request.failure})
            if len(report['failed_requests']) < 30 else None)
        page.goto(BASE + '/.login', wait_until='domcontentloaded')
        page.locator('input[name="username"]').fill(credentials['username'])
        page.locator('input[name="password"]').fill(credentials['password'])
        page.get_by_role('button', name='Log in', exact=True).click()
        page.wait_for_timeout(1500)
        assert page.locator('input[name="password"]').count() == 0, page.locator('body').inner_text()[:1000]
        report['checks']['browser_login'] = True

        # MCP OAuth uses local dynamic registration and PKCE; no remote
        # metadata document or remote identity provider is involved.
        api = context.request
        registration = api.post(BASE + '/.auth/register', data={
            'client_name': 'Offline acceptance test',
            'redirect_uris': [BASE + '/offline-oauth-callback'],
            'token_endpoint_auth_method': 'none'})
        assert registration.status == 201, registration.text()
        client_id = registration.json()['client_id']
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        params = {'response_type': 'code', 'client_id': client_id,
            'redirect_uri': BASE + '/offline-oauth-callback', 'scope': 'mcp',
            'resource': BASE + '/.mcp', 'state': secrets.token_urlsafe(16),
            'code_challenge': challenge, 'code_challenge_method': 'S256'}
        page.goto(BASE + '/.auth/mcp/authorize?' + urllib.parse.urlencode(params))
        page.get_by_role('button', name='Allow', exact=True).wait_for()
        page.get_by_role('button', name='Allow', exact=True).click()
        page.wait_for_url(BASE + '/offline-oauth-callback?*')
        callback = urllib.parse.parse_qs(urllib.parse.urlsplit(page.url).query)
        assert callback['state'][0] == params['state']
        response = api.post(BASE + '/.auth/mcp/token', form={
            'grant_type': 'authorization_code', 'code': callback['code'][0],
            'client_id': client_id, 'redirect_uri': params['redirect_uri'],
            'code_verifier': verifier, 'resource': BASE + '/.mcp'})
        assert response.status == 200, response.text()
        token = response.json()['access_token']
        report['checks']['mcp_local_oauth_pkce'] = True
        rpc_id = 0
        def rpc(method, params):
            nonlocal rpc_id
            rpc_id += 1
            response = api.post(BASE + '/.mcp', headers={'Authorization': 'Bearer ' + token,
                'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25'},
                data={'jsonrpc': '2.0', 'id': rpc_id, 'method': method, 'params': params})
            assert response.status == 200, response.text()
            result = response.json()
            assert 'error' not in result, result
            return result['result']
        initialized = rpc('initialize', {'protocolVersion': '2025-11-25',
            'clientInfo': {'name': 'offline-test', 'version': '1'}, 'capabilities': {}})
        report['mcp_server'] = initialized.get('serverInfo')
        tools = rpc('tools/list', {})['tools']
        report['mcp_tools'] = [tool['name'] for tool in tools]
        def call(name, args):
            result = rpc('tools/call', {'name': name, 'arguments': args})
            assert not result.get('isError'), result
            return result
        previous = Path(args.previous_report) if args.previous_report else ROOT / 'absent-previous-report.json'
        if previous.exists():
            old_note = json.loads(previous.read_text())['created_note']
            old_read = call('read', {'space': 'Synthetic runtime test', 'page': old_note})
            assert 'Saved through the offline browser' in json.dumps(old_read)
            report['checks']['note_persisted_across_server_restart'] = True
        help_result = call('help', {})
        assert 'Synthetic runtime test' in json.dumps(help_result)
        space = 'Synthetic runtime test'
        note_name = 'Offline acceptance ' + time.strftime('%Y%m%d-%H%M%S')
        marker = 'OFFLINECHECK' + secrets.token_hex(5)
        content = '# Offline acceptance\n\n' + marker + '\n\n[[index]]\n'
        call('write', {'space': space, 'page': note_name, 'content': content})
        read = call('read', {'space': space, 'page': note_name})
        assert marker in json.dumps(read)
        meta = read['structuredContent']
        conflict = rpc('tools/call', {'name': 'write', 'arguments': {
            'space': space, 'page': note_name, 'content': 'must not overwrite'}})
        assert conflict.get('isError'), conflict
        call('edit', {'space': space, 'page': note_name, 'ifRevision': meta['revision'],
            'edits': [{'oldText': 'Offline acceptance', 'newText': 'Offline acceptance verified'}]})
        search = call('search', {'space': space, 'text': marker, 'mode': 'words'})
        assert note_name in json.dumps(search), search
        report['checks']['mcp_initialize_list_help_write_read_edit_search'] = True
        report['checks']['mcp_prevents_blind_overwrite'] = True
        disabled_runtime = rpc('tools/call', {'name': 'lua', 'arguments': {
            'space': space, 'code': 'return 1'}})
        assert disabled_runtime.get('isError'), disabled_runtime
        assert 'runtime API is not available' in json.dumps(disabled_runtime)
        report['checks']['runtime_api_disabled'] = True

        report['filesystem_responses'] = []
        for resource in ['/.fs', '/.fs/Library/Std/Plugs/editor.plug.js']:
            check_response = api.get(BASE + resource)
            report['filesystem_responses'].append({'path': resource, 'status': check_response.status,
                'headers': {k: v for k, v in check_response.headers.items()
                            if k in ['content-type', 'location', 'cross-origin-resource-policy']},
                'sample': check_response.text()[:100]})

        page.goto(BASE + '/' + urllib.parse.quote(note_name), wait_until='domcontentloaded')
        editor = page.locator('.cm-content[contenteditable="true"]').first
        editor.wait_for(timeout=30000)
        try:
            page.wait_for_function("marker => document.querySelector('.cm-content')?.textContent.includes(marker)",
                                   arg=marker, timeout=30000)
        except Exception:
            report['editor_failure_body'] = page.locator('body').inner_text()[:2000]
            raise
        assert marker in editor.inner_text(), editor.inner_text()
        editor.click()
        page.keyboard.press('Control+End')
        page.keyboard.press('Enter')
        ui_marker = 'Saved through the offline browser'
        page.keyboard.insert_text(ui_marker)
        for _ in range(100):
            if ui_marker in json.dumps(call('read', {'space': space, 'page': note_name})):
                break
            page.wait_for_timeout(100)
        else:
            raise AssertionError('Browser edit did not reach the server')
        page.reload(wait_until='domcontentloaded')
        editor.wait_for(timeout=30000)
        page.wait_for_timeout(1500)
        assert ui_marker in editor.inner_text()
        page.screenshot(path=ROOT / 'evidence/offline-browser.png', full_page=True)
        report['checks']['browser_read_edit_save_reload'] = True
        report['created_note'] = note_name
        # First record ordinary operation; deliberate external probes below
        # are not counted as naturally occurring external requests.
        report['ordinary_browser_external_requests'] = list(report['browser_external_requests'])
        report['ordinary_browser_errors'] = list(report['browser_errors'])
        assert not report['ordinary_browser_external_requests'], report['ordinary_browser_external_requests']
        report['checks']['ordinary_browser_same_origin_only'] = True
        csp = api.get(BASE + '/.login').headers.get('content-security-policy', '')
        assert "connect-src 'self'" in csp
        denied = page.evaluate("""async () => {
          const blocked = {};
          try { await fetch('https://198.51.100.10/offline-check'); blocked.fetch = false; }
          catch (e) { blocked.fetch = String(e).includes('Offline build'); }
          for (const name of ['WebSocket', 'EventSource']) {
            try { new globalThis[name]((name === 'WebSocket' ? 'wss:' : 'https:') + '//198.51.100.10/offline-check'); blocked[name] = false; }
            catch (e) { blocked[name] = String(e).includes('Offline build'); }
          }
          return blocked;
        }""")
        assert all(denied.values()), denied
        report['checks']['browser_rejects_external_targets_before_transport'] = denied
        assert not report['browser_external_requests'], report['browser_external_requests']
        proxy = api.get(BASE + '/.proxy/198.51.100.10/offline-check', headers={'X-Proxy-Request': 'true'})
        assert proxy.status == 403 and 'Offline build' in proxy.text(), (proxy.status, proxy.text()[:300])
        report['checks']['outbound_proxy_implementation_removed'] = True
        external = dict(params)
        external['client_id'] = 'https://198.51.100.10/client.json'
        external_response = api.get(BASE + '/.auth/mcp/authorize?' + urllib.parse.urlencode(external))
        assert external_response.status == 400, external_response.status
        report['checks']['external_client_metadata_fails_locally'] = True
        browser.close()
    report['passed'] = True

if __name__ == '__main__':
    try:
        main()
    except Exception:
        report['failure'] = traceback.format_exc()
    Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    if not report['passed']:
        print(report['failure'])
    raise SystemExit(0 if report['passed'] else 1)
