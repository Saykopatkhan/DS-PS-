# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

from flask import Flask
app = Flask(__name__)
class TestApp:
    def __init__(self):
        self.app = app
        self._register_routes()
    def _register_routes(self):
        print("Registering routes...")
        @self.app.route('/')
        def index():
            return "hello"
        print("Done registering routes.")

t = TestApp()
print(t.app.url_map)
