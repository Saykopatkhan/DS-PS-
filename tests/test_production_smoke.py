"""Exercise the real single-worker Gunicorn entrypoint on loopback in IDS mode."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

import requests


def test_gunicorn_login_authenticated_api_and_clean_shutdown(tmp_path):
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    environment = os.environ.copy()
    environment.update(DS_IPS_MODE='ids', DS_IPS_INTERFACE='lo', DS_IPS_HIDS='false',
                       DS_IPS_TELEGRAM='false', DS_IPS_DRY_RUN='true',
                       DS_IPS_DB=str(tmp_path / 'production.db'),
                       DS_IPS_USER='smoke', DS_IPS_PASSWORD='smoke-test-password',
                       DS_IPS_TRUST_PROXY='false', DS_IPS_COOKIE_SECURE='false')
    with (tmp_path / 'gunicorn.log').open('w+') as output:
        process = subprocess.Popen(
            [sys.executable, '-m', 'gunicorn', '--worker-class', 'gthread', '--workers', '1',
             '--threads', '2', '--bind', f'127.0.0.1:{port}', 'wsgi:app'],
            cwd=Path(__file__).resolve().parents[1], env=environment,
            stdout=output, stderr=subprocess.STDOUT,
        )
        try:
            with requests.Session() as client:
                client.trust_env = False
                url = f'http://127.0.0.1:{port}'
                deadline = time.monotonic() + 15
                while True:
                    assert process.poll() is None, 'Gunicorn exited during startup'
                    try:
                        response = client.get(url + '/login', timeout=1)
                        break
                    except (requests.ConnectionError, requests.Timeout):
                        if time.monotonic() > deadline:
                            raise
                        time.sleep(0.1)
                assert response.status_code == 200
                assert client.get(url + '/api/stats', timeout=2).status_code == 401
                token = re.search(r'name="csrf_token" value="([^"]+)"', response.text).group(1)
                response = client.post(url + '/login', data={'username': 'smoke', 'password': 'smoke-test-password',
                                                            'csrf_token': token}, allow_redirects=False, timeout=2)
                assert response.status_code == 302
                stats = client.get(url + '/api/stats', timeout=2)
                assert stats.status_code == 200
                assert stats.json()['sniffer_running'] is False
                assert stats.json()['mode'] == 'IDS'
                handshake = client.get(url + '/socket.io/?EIO=4&transport=polling', timeout=2)
                assert handshake.status_code == 200
                assert json.loads(handshake.text[1:])['sid']
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        output.seek(0)
        logs = output.read()
        assert process.returncode == 0, logs
        assert 'Traceback' not in logs, logs
