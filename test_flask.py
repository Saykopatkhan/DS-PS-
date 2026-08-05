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
