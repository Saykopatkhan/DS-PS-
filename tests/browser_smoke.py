"""Manual browser regression: PYTHONPATH=. python tests/browser_smoke.py.

Requires Playwright and Chromium. Uses a disposable database, loopback HTTP,
and passive IDS mode; does not start packet capture or active defenses.
"""
import os
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from web.app import IPSWebApp


def wait_for_js(page, expression):
    # Evaluate directly through the browser protocol: wait_for_function's
    # internal eval is blocked by this panel's Content Security Policy.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if page.evaluate(expression):
            return
        page.wait_for_timeout(50)
    raise AssertionError(f'Browser condition not reached: {expression}')


def check_live_visuals(page, panel):
    from datetime import datetime, timezone
    stamp = datetime.now(timezone.utc).isoformat()
    records = [{'ip_address': f'192.0.2.{i}', 'mac_address': f'02:00:00:00:00:{i:02x}',
                'hostname': f'Client {i}', 'last_seen': stamp, 'os_type': 'Linux'} for i in range(1, 101)]
    stats = panel._get_stats()
    stats.update(sniffer_running=True, monitoring_requested=True,
                 capture={'scapy': {'running': True, 'packets': 20, 'last_packet_at': 1000},
                          'tshark': {'running': True, 'packets': 20, 'last_packet_at': 1000}})
    page.route('**/api/devices', lambda route: route.fulfill(json=records))
    page.route('**/api/stats', lambda route: route.fulfill(json=stats))
    try:
        page.reload()
        wait_for_js(page, 'nodes.length === 101')
        assert page.locator('#general-traffic-body tr').count() == 100
        assert page.evaluate('nodes.get("192.0.2.1") !== null')
        # Fixed measured node boxes cannot overlap, including reduced motion.
        def check_nodes():
            assert page.evaluate('''() => {
                const boxes = nodes.getIds().map(id => network.getBoundingBox(id));
                return boxes.every((a, i) => boxes.slice(i + 1).every(b =>
                    a.right < b.left || b.right < a.left || a.bottom < b.top || b.bottom < a.top));
            }'''), 'Device boxes overlap'
        check_nodes()
        before = page.evaluate('network.getPositions()')
        page.evaluate('fetchRecordsForTrafficList()')
        assert page.evaluate('network.getPositions()') == before
        page.emulate_media(reduced_motion='reduce')
        page.wait_for_timeout(100)
        check_nodes()
        assert page.evaluate('radarFrame === null')
        page.emulate_media(reduced_motion='no-preference')
        page.locator('#radar-canvas').scroll_into_view_if_needed()
        wait_for_js(page, 'isRunning && radarFrame !== null')
        angle = page.evaluate('radarAngle')
        page.wait_for_timeout(180)
        assert page.evaluate('radarAngle') != angle
        page.locator('#tab-geo').click()
        page.wait_for_timeout(120)
        page.locator('#tab-radar').click()
        page.wait_for_timeout(180)
        angle = page.evaluate('radarAngle')
        page.wait_for_timeout(180)
        assert page.evaluate('radarAngle') != angle
        panel.socketio.emit('new_alert', {'id': 999, 'source_ip': '192.0.2.2',
            'destination_ip': '192.0.2.3', 'alert_type': 'Visual observation',
            'severity': 'low', 'description': 'Offline fixture'})
        wait_for_js(page, 'radarBlips.some(b => b.label === "192.0.2.2")')
        page.evaluate('addRadarBlip("192.0.2.2", "critical"); addRadarBlip("192.0.2.2", "low")')
        assert page.evaluate('radarBlips.find(b => b.label === "192.0.2.2").severity') == 'critical'
        page.evaluate('drawAttackLaser("198.51.100.2", "198.51.100.3", "high")')
        assert page.evaluate('nodes.length') == 101
        page.evaluate('updateNetworkMap([])')
        assert page.evaluate('nodes.getIds()') == ['gateway']
        assert page.evaluate('edges.length') == 0
        page.set_viewport_size({'width': 390, 'height': 844})
        page.evaluate('fetchRecordsForTrafficList()')
        wait_for_js(page, 'nodes.length === 101')
        check_nodes()
        check_layout(page)
    finally:
        page.unroute('**/api/devices')
        page.unroute('**/api/stats')
        page.set_viewport_size({'width': 1440, 'height': 1000})
        page.reload()
        wait_for_js(page, 'socket && socket.connected')


def check_layout(page):
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 1'), 'Page overflows horizontally'
    assert page.evaluate('''() => {
        const ids = [...document.querySelectorAll('[id]')].map(node => node.id);
        return ids.length === new Set(ids).size;
    }'''), 'Duplicate element IDs'


def screenshot(page, name):
    destination = os.environ.get('DS_IPS_SCREENSHOTS')
    if destination:
        path = Path(destination)
        path.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(path / (name + '.png')), full_page=True)
        page.screenshot(path=str(path / (name + '-viewport.png')))


def main():
    os.environ.update(DS_IPS_USER='browser-test', DS_IPS_PASSWORD='browser-test-password',
                      DS_IPS_COOKIE_SECURE='false', DS_IPS_TRUST_PROXY='false')
    with tempfile.TemporaryDirectory(prefix='dsips-browser-') as directory:
        panel = IPSWebApp(interface='lo', mode='ids', db_path=str(Path(directory) / 'test.db'))
        panel.dns_sinkhole.blocklist_path = str(Path(directory) / 'blocklist.json')
        server = make_server('127.0.0.1', 0, panel.app, threaded=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        errors = []
        failures = []
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(executable_path='/usr/bin/chromium', headless=True,
                                                       args=['--no-sandbox'])
                context = browser.new_context(viewport={'width': 1440, 'height': 1000})
                context.route('**/*', lambda route: route.continue_() if urlparse(route.request.url).hostname == '127.0.0.1'
                              else route.fulfill(status=200, body=''))
                page = context.new_page()
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.on('response', lambda response: failures.append((response.status, response.url))
                        if '/api/' in response.url and response.status >= 400 else None)
                base = f'http://127.0.0.1:{server.server_port}'
                page.goto(base + '/login')
                page.wait_for_timeout(800)
                check_layout(page)
                screenshot(page, 'login-desktop')
                page.locator('.password-toggle').click()
                assert page.locator('#password').get_attribute('type') == 'text'
                page.locator('.password-toggle').click()
                page.locator('#username').fill(panel.admin_user)
                page.locator('#password').fill(panel.admin_pass)
                page.locator('button[type="submit"]').click()
                page.wait_for_url(base + '/')
                page.wait_for_timeout(800)
                assert page.evaluate('() => Boolean(socket && socket.connected)')
                assert page.evaluate('typeof Lenis === "function" && typeof anime.animate === "function"')
                assert not page.locator('[data-toggle-nav]').is_visible()
                check_layout(page)
                screenshot(page, 'dashboard-desktop')
                check_live_visuals(page, panel)
                page.locator('#tab-geo').click()
                page.locator('#leaflet-map path').first.wait_for(state='attached')
                assert page.evaluate('geoMapInitialized && Boolean(geoMap)')
                assert page.locator('#leaflet-map path').count() > 10
                screenshot(page, 'geography-desktop')
                page.locator('#tab-radar').click()
                # Exercise rendering with an untrusted device hostname and alarm.
                payload = '<img src=x onerror="window.dsipsXss=true">'
                panel.db.update_ip_mac('192.0.2.10', '02:00:00:00:00:10', hostname=payload)
                panel.db.add_alert('Test ' + payload, '192.0.2.10', None, None, None, payload, 'low')
                page.evaluate('fetchRecordsForTrafficList()')
                page.wait_for_timeout(500)
                assert page.evaluate('window.dsipsXss !== true')
                assert payload in page.locator('#general-traffic-body').inner_text()
                page.evaluate("async () => renderDeviceList(await (await apiFetch('/api/devices')).json())")
                assert payload in page.locator('#scanner-list').inner_text()
                assert page.locator('#hids-alerts').inner_text() == '0'
                # The correlated incident UI is advisory in default IDS mode.
                page.evaluate('fetchIncidentOverview()')
                expect(page.locator('#response-policy-status')).to_contain_text('kapalı (değerlendirme)')
                expect(page.locator('#incident-table-body')).to_contain_text('192.0.2.10')
                expect(page.locator('#incident-table-body')).to_contain_text('İzle')
                page.evaluate("filterAlerts('critical')")
                page.evaluate("addAlertToFeed({severity:'low', alert_type:'Filter regression', description:'Hidden event'}, true)")
                assert not page.locator('.alert-item').filter(has_text='Filter regression').is_visible()
                assert page.locator('.filter-empty').is_visible()
                page.evaluate("filterAlerts('all')")
                assert page.locator('.alert-item').filter(has_text='Filter regression').is_visible()
                await_response = page.expect_response('**/api/settings')
                with await_response:
                    page.evaluate('openSettings()')
                page.locator('#setting-telegram-chat').fill('')
                with page.expect_response(lambda response: '/api/settings' in response.url and response.request.method == 'POST') as saved:
                    page.evaluate('saveSettings()')
                assert saved.value.ok
                # Keyboard focus is trapped in dialogs and Escape releases the page.
                page.locator('.nav-bottom button').first.click()
                page.locator('#settings-modal').wait_for(state='visible')
                expect(page.locator('.app-workspace')).to_have_attribute('inert', '')
                for _ in range(9):
                    page.keyboard.press('Tab')
                    assert page.evaluate('Boolean(document.activeElement.closest("#settings-modal"))')
                page.keyboard.press('Escape')
                page.locator('#settings-modal').wait_for(state='hidden')
                assert not page.evaluate('document.querySelector(".app-workspace").inert')
                # Mobile menu, nested scrolling, responsive layout and reduced motion.
                page.set_viewport_size({'width': 390, 'height': 844})
                page.emulate_media(reduced_motion='reduce')
                page.evaluate('window.scrollTo(0, 0)')
                page.wait_for_timeout(200)
                check_layout(page)
                assert not page.evaluate('document.documentElement.classList.contains("lenis")')
                assert page.evaluate('radarFrame === null')
                screenshot(page, 'dashboard-mobile')
                for width in (320, 768):
                    page.set_viewport_size({'width': width, 'height': 900})
                    check_layout(page)
                page.set_viewport_size({'width': 390, 'height': 844})
                page.locator('[data-toggle-nav]').click()
                assert page.locator('[data-toggle-nav]').get_attribute('aria-expanded') == 'true'
                page.locator('.nav-link[data-section="network"]').click()
                assert not page.evaluate('document.body.classList.contains("nav-open")')
                assert page.evaluate('document.activeElement.id') == 'network'
                page.evaluate('openSettings()')
                page.locator('#settings-modal').wait_for(state='visible')
                check_layout(page)
                page.keyboard.press('Escape')
                page.locator('#settings-modal').wait_for(state='hidden')
                page.goto(base + '/soc_premium')
                page.wait_for_timeout(500)
                assert page.evaluate('window.dsipsXss !== true')
                check_layout(page)
                page.evaluate("showPortModal('192.0.2.10', [22, 443])")
                page.locator('#port-modal').wait_for(state='visible')
                assert 'SSH' in page.locator('#port-modal-body').inner_text()
                page.keyboard.press('Escape')
                page.locator('#port-modal').wait_for(state='hidden')
                # Recoverable request failures must replace the loading/empty state.
                page.route('**/api/ueba_profiles', lambda route: route.abort())
                page.evaluate('refreshData()')
                assert 'Veriler alınamadı' in page.locator('#ueba-body').inner_text()
                page.unroute('**/api/ueba_profiles')
                page.evaluate('refreshData()')
                assert 'Henüz davranış profili yok' in page.locator('#ueba-body').inner_text()
                screenshot(page, 'analysis-mobile')
                page.set_viewport_size({'width': 1440, 'height': 1000})
                check_layout(page)
                screenshot(page, 'analysis-desktop')
                page.evaluate('logout()')
                page.wait_for_url(base + '/login')
                page.set_viewport_size({'width': 390, 'height': 844})
                check_layout(page)
                screenshot(page, 'login-mobile')
                # This denial is expected after logout, not an API smoke failure.
                assert context.request.get(base + '/api/stats').status == 401
                browser.close()
            assert not errors, errors
            assert not failures, failures
            print('Browser smoke passed: login, Socket.IO, device/XSS rendering, live filters, settings, keyboard dialogs, mobile navigation, reduced motion, analysis, logout.')
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)
            panel.close()


if __name__ == '__main__':
    main()
