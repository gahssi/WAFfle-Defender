import http.server
import socketserver
import json
from langchain_ollama import OllamaLLM

llm = OllamaLLM(model="llama3.2:latest")

class IntermediaryHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)  # Read incoming data
        
        try:
            query_data = json.loads(post_data)
            prompt = query_data.get("prompt", "")
            print(prompt)
            if not prompt:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "Prompt is required"}')
                return
            
            response_text = llm.invoke(prompt)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = {"response": response_text}
            self.wfile.write(json.dumps(response).encode("utf-8"))
        
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            error_message = {"error": str(e)}
            self.wfile.write(json.dumps(error_message).encode("utf-8"))

def run_server():
    host = "0.0.0.0"  
    port = 5000       
    with socketserver.TCPServer((host, port), IntermediaryHandler) as httpd:
        print(f"Serving on {host}:{port}")
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()
