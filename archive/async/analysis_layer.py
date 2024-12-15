import os
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import logging
from http.cookies import SimpleCookie
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from rule_updater import process_injections

logger = logging.getLogger('analysis_layer')
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler('analysis_layer.log')
fh.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

logger.addHandler(fh)

REGEX_RULES_FILE = 'regex_rules.txt'
INJECTION_LOG_FILE = 'injection.tmp'

regex_rules = []

def load_regex_rules():
    global regex_rules
    try:
        with open(REGEX_RULES_FILE, 'r') as f:
            regex_rules.clear()
            for line in f:
                pattern = line.strip()
                if pattern:
                    try:
                        compiled_pattern = re.compile(pattern)
                        regex_rules.append(compiled_pattern)
                    except re.error as e:
                        logger.error(f"Invalid regex pattern '{pattern}': {e}")
        logger.info(f"Loaded {len(regex_rules)} regex rules from {REGEX_RULES_FILE}")
    except Exception as e:
        logger.error(f"Error loading regex rules from {REGEX_RULES_FILE}: {e}")
        regex_rules = []

load_regex_rules()

BACKEND_SERVER_URL = 'http://localhost'

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        process_injections()
        self.process_request('GET')

    def do_POST(self):
        self.process_request('POST')

    def process_request(self, method):
        try:
            parsed_url = urllib.parse.urlparse(self.path)

            query_params = urllib.parse.parse_qs(parsed_url.query)

            post_params = {}
            post_body = b''
            if method == 'POST':
                content_length = int(self.headers.get('Content-Length', 0))
                post_body = self.rfile.read(content_length)
                post_params = urllib.parse.parse_qs(post_body.decode('utf-8'))

            all_params = {**query_params, **post_params}

            logger.info(f"Received {method} request to {self.path}")
            logger.info(f"Query params: {query_params}")

            for param_values in all_params.values():
                for value in param_values:
                    decoded_value = urllib.parse.unquote_plus(value)
                    self.log_injection(decoded_value)
                    for compiled_pattern in regex_rules:
                        if compiled_pattern.search(decoded_value):
                            logger.info(f"Blocked request from {self.client_address[0]}: {decoded_value}")
                            
                            self.send_response(403)
                            self.send_header('Content-Type', 'text/html')
                            self.end_headers()
                            self.wfile.write(b'Forbidden: SQL Injection detected by WAFfle Defender.')
                            return

            self.forward_request(method, parsed_url, post_body)
        except Exception as e:
            logger.error(f"Error in process_request: {e}", exc_info=True)
            self.send_error(500, 'Internal Server Error')

    def forward_request(self, method, parsed_url, post_body):
        try:
            backend_url = f"{BACKEND_SERVER_URL}{parsed_url.path}"
            if parsed_url.query:
                backend_url = backend_url + f"?{parsed_url.query}"

            logger.info(f"Forwarding request to backend URL: {backend_url}")

            headers = {key: value for key, value in self.headers.items() if key.lower() not in ['host', 'connection']}

            headers['Host'] = 'localhost'

            # Add custom header to identify requests from the analysis layer
            headers['X-Forwarded-By'] = 'analysis_layer'

            cookies = {}
            if 'Cookie' in self.headers:
                cookie = SimpleCookie()
                cookie.load(self.headers.get('Cookie'))
                cookies = {key: morsel.value for key, morsel in cookie.items()}

            if method == 'GET':
                response = requests.get(backend_url, headers=headers, cookies=cookies, allow_redirects=False)
            elif method == 'POST':
                response = requests.post(backend_url, headers=headers, data=post_body, cookies=cookies, allow_redirects=False)
            else:
                self.send_error(501, 'HTTP Method Not Implemented')
                return

            logger.info(f"Received response with status code: {response.status_code}")

            self.send_response_only(response.status_code)

            for key, value in response.raw.headers.items():
                if key.lower() != 'connection':
                    if key.lower() == 'set-cookie':
                        for val in response.raw.headers.get_all(key):
                            self.send_header(key, val)
                    else:
                        self.send_header(key, value)

            logger.debug(f"Response headers sent to client: {self._headers_buffer}")

            self.end_headers()

            self.wfile.write(response.content)

        except requests.exceptions.RequestException as e:
            logger.error(f"Error forwarding request: {e}", exc_info=True)
            self.send_error(502, f'Bad Gateway: {e}')

        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            self.send_error(500, f'Internal Server Error')

    def log_injection(self, decoded_value):
        try:
            with open(INJECTION_LOG_FILE, 'a') as f:
                f.write(decoded_value + '\n')
        except Exception as e:
            logger.error(f"Error writing to injection log file: {e}")

class RegexRulesEventHandler(PatternMatchingEventHandler):
    def __init__(self):
        super().__init__(patterns=[REGEX_RULES_FILE])

    def on_modified(self, event):
        logger.info(f"Detected change in regex rules file: {event.src_path}")
        load_regex_rules()
        
def start_regex_rules_monitor():
    event_handler = RegexRulesEventHandler()
    observer = Observer()
    directory = os.path.dirname(REGEX_RULES_FILE) or '.'
    observer.schedule(event_handler, path=directory, recursive=False)
    observer.start()
    logger.info("Started monitoring regex rules file for changes.")
    return observer

def run_server(server_class=HTTPServer, handler_class=RequestHandler, port=8080):
    observer = start_regex_rules_monitor()

    try:
        server_address = ('0.0.0.0', port)
        httpd = server_class(server_address, handler_class)
        print(f'Starting analysis layer on port {port}...')
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
        logger.info("Stopped monitoring regex rules file.")

if __name__ == '__main__':
    run_server()
