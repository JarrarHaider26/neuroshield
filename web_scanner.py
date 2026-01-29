#!/usr/bin/env python3
"""
Web-based Malware Scanner with File Upload
Simple Flask app for scanning PE files through a web interface.
Includes CORS support for integration with Next.js frontend.
"""

import os
import tempfile
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from werkzeug.utils import secure_filename
from malware_scanner import MalwareScanner

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max

# Initialize scanner
scanner = None

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>NeuroShield Malware Scanner</title>
    <style>
        * { box-sizing: border-box; font-family: 'Segoe UI', Arial, sans-serif; }
        body { 
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh; margin: 0; padding: 20px;
            display: flex; justify-content: center; align-items: center;
        }
        .container { 
            background: #fff; border-radius: 16px; padding: 40px;
            max-width: 600px; width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { color: #1a1a2e; margin: 0 0 10px 0; font-size: 28px; }
        .subtitle { color: #666; margin-bottom: 30px; }
        .upload-area {
            border: 3px dashed #ddd; border-radius: 12px; padding: 40px;
            text-align: center; cursor: pointer; transition: all 0.3s;
            background: #f8f9fa;
        }
        .upload-area:hover { border-color: #4a90d9; background: #e8f4fd; }
        .upload-area.dragover { border-color: #4a90d9; background: #e8f4fd; }
        .upload-icon { font-size: 48px; margin-bottom: 10px; }
        input[type="file"] { display: none; }
        .btn {
            background: linear-gradient(135deg, #4a90d9 0%, #357abd 100%);
            color: white; border: none; padding: 14px 32px; border-radius: 8px;
            font-size: 16px; cursor: pointer; margin-top: 20px; transition: all 0.3s;
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(74,144,217,0.4); }
        .btn:disabled { background: #ccc; cursor: not-allowed; transform: none; }
        .result {
            margin-top: 30px; padding: 25px; border-radius: 12px;
            display: none; animation: fadeIn 0.5s;
        }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .result.malicious { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a5a 100%); color: white; }
        .result.benign { background: linear-gradient(135deg, #51cf66 0%, #40c057 100%); color: white; }
        .result.error { background: linear-gradient(135deg, #ffd43b 0%, #fab005 100%); color: #333; }
        .verdict { font-size: 32px; font-weight: bold; margin-bottom: 15px; }
        .details { font-size: 14px; opacity: 0.9; }
        .details p { margin: 8px 0; }
        .confidence-bar {
            height: 8px; background: rgba(255,255,255,0.3); border-radius: 4px;
            margin-top: 15px; overflow: hidden;
        }
        .confidence-fill { height: 100%; background: white; border-radius: 4px; transition: width 0.5s; }
        .loading { display: none; text-align: center; margin-top: 20px; }
        .spinner {
            width: 40px; height: 40px; border: 4px solid #f3f3f3;
            border-top: 4px solid #4a90d9; border-radius: 50%;
            animation: spin 1s linear infinite; margin: 0 auto 10px;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .file-info { margin-top: 15px; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ NeuroShield Malware Scanner</h1>
        <p class="subtitle">Upload a Windows executable (.exe, .dll) to scan for malware</p>
        
        <form id="uploadForm" enctype="multipart/form-data">
            <div class="upload-area" id="dropZone" onclick="document.getElementById('fileInput').click()">
                <div class="upload-icon">📁</div>
                <p><strong>Click to select</strong> or drag & drop a file here</p>
                <p style="font-size: 12px; color: #999;">Supported: .exe, .dll, .sys (max 100MB)</p>
            </div>
            <input type="file" id="fileInput" name="file" accept=".exe,.dll,.sys,.scr">
            <div class="file-info" id="fileInfo"></div>
            <button type="submit" class="btn" id="scanBtn" disabled>🔍 Scan File</button>
        </form>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p>Analyzing file... This may take a few seconds.</p>
        </div>
        
        <div class="result" id="result">
            <div class="verdict" id="verdict"></div>
            <div class="details" id="details"></div>
            <div class="confidence-bar"><div class="confidence-fill" id="confidenceFill"></div></div>
        </div>
    </div>

    <script>
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const fileInfo = document.getElementById('fileInfo');
        const scanBtn = document.getElementById('scanBtn');
        const loading = document.getElementById('loading');
        const result = document.getElementById('result');
        
        // Drag and drop
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(e => {
            dropZone.addEventListener(e, ev => { ev.preventDefault(); ev.stopPropagation(); });
        });
        ['dragenter', 'dragover'].forEach(e => dropZone.addEventListener(e, () => dropZone.classList.add('dragover')));
        ['dragleave', 'drop'].forEach(e => dropZone.addEventListener(e, () => dropZone.classList.remove('dragover')));
        
        dropZone.addEventListener('drop', e => {
            fileInput.files = e.dataTransfer.files;
            updateFileInfo();
        });
        
        fileInput.addEventListener('change', updateFileInfo);
        
        function updateFileInfo() {
            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];
                const size = (file.size / 1024 / 1024).toFixed(2);
                fileInfo.innerHTML = `<strong>Selected:</strong> ${file.name} (${size} MB)`;
                scanBtn.disabled = false;
                result.style.display = 'none';
            }
        }
        
        document.getElementById('uploadForm').addEventListener('submit', async e => {
            e.preventDefault();
            
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            
            scanBtn.disabled = true;
            loading.style.display = 'block';
            result.style.display = 'none';
            
            try {
                const response = await fetch('/scan', { method: 'POST', body: formData });
                const data = await response.json();
                
                loading.style.display = 'none';
                result.style.display = 'block';
                
                result.className = 'result ' + (data.error ? 'error' : data.verdict.toLowerCase());
                
                if (data.error) {
                    document.getElementById('verdict').textContent = '⚠️ Error';
                    document.getElementById('details').innerHTML = `<p>${data.error}</p>`;
                    document.getElementById('confidenceFill').style.width = '0%';
                } else {
                    const icon = data.verdict === 'Malicious' ? '🚨' : '✅';
                    document.getElementById('verdict').textContent = icon + ' ' + data.verdict;
                    document.getElementById('details').innerHTML = `
                        <p><strong>Confidence:</strong> ${(data.confidence * 100).toFixed(1)}%</p>
                        <p><strong>Malware Probability:</strong> ${(data.malware_probability * 100).toFixed(1)}%</p>
                        <p><strong>Threat Severity:</strong> ${data.threat_severity}</p>
                        <p><strong>SHA256:</strong> ${data.file_hash.substring(0, 32)}...</p>
                    `;
                    document.getElementById('confidenceFill').style.width = (data.confidence * 100) + '%';
                }
            } catch (err) {
                loading.style.display = 'none';
                result.style.display = 'block';
                result.className = 'result error';
                document.getElementById('verdict').textContent = '⚠️ Error';
                document.getElementById('details').innerHTML = `<p>Failed to scan file: ${err.message}</p>`;
            }
            
            scanBtn.disabled = false;
        });
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    """Serve the main page."""
    return render_template_string(HTML_TEMPLATE)

@app.route('/scan', methods=['POST'])
def scan_file():
    """Handle file upload and scanning."""
    global scanner
    
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Validate extension
    allowed = {'.exe', '.dll'}
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in allowed:
        return jsonify({"error": f"Invalid file type. Allowed: {', '.join(allowed)}"}), 400
    
    # Save to temp file with short name to avoid Windows path length issues
    temp_dir = tempfile.gettempdir()
    original_filename = secure_filename(file.filename)
    ext = os.path.splitext(original_filename)[1].lower()
    # Use short random name to avoid path length issues
    import uuid
    short_name = f"scan_{uuid.uuid4().hex[:8]}{ext}"
    temp_path = os.path.join(temp_dir, short_name)
    
    try:
        file.save(temp_path)
        
        # Scan the file
        result = scanner.scan(temp_path)
        
        # Clean up
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        
        try:
            return jsonify(result)
        except TypeError as e:
            # Fallback for JSON serialization errors (e.g. numpy types)
            import json
            class NumpyEncoder(json.JSONEncoder):
                def default(self, obj):
                    if hasattr(obj, 'tolist'):
                        return obj.tolist()
                    if hasattr(obj, 'item'):
                        return obj.item()
                    return super().default(obj)
            
            return app.response_class(
                response=json.dumps(result, cls=NumpyEncoder),
                status=200,
                mimetype='application/json'
            )
            
    except Exception as e:
        # Clean up on error
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        
        # Log the full error
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "scanner": scanner is not None})

@app.route('/info')
def info():
    """Get scanner info."""
    global scanner
    if scanner:
        return jsonify(scanner.get_info())
    return jsonify({"error": "Scanner not initialized"}), 500

@app.route('/test')
def test():
    """Quick test endpoint to verify API is responsive."""
    import time
    start = time.time()
    response_time = (time.time() - start) * 1000
    return jsonify({
        "status": "ok",
        "message": "NeuroShield API is running",
        "response_time_ms": round(response_time, 2),
        "scanner_ready": scanner is not None
    })

@app.route('/scan-url', methods=['POST'])
def scan_url():
    """
    Proxy endpoint for VirusTotal URL scanning.
    Keeps API keys secure on the server side.
    """
    import time
    import requests
    
    # Get VirusTotal API keys from environment variables
    vt_api_keys = os.environ.get('VIRUSTOTAL_API_KEYS', '').split(',')
    if not vt_api_keys or vt_api_keys[0] == '':
        return jsonify({"error": "VirusTotal API keys not configured"}), 500
    
    # Get URL from request
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400
    
    url_to_scan = data['url']
    
    # Validate URL
    if not url_to_scan.startswith('http://') and not url_to_scan.startswith('https://'):
        return jsonify({"error": "Invalid URL format"}), 400
    
    # Use first available API key (you can implement rotation logic here)
    api_key = vt_api_keys[0].strip()
    
    try:
        # Submit URL to VirusTotal
        submit_response = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers={'x-apikey': api_key, 'Content-Type': 'application/x-www-form-urlencoded'},
            data={'url': url_to_scan},
            timeout=10
        )
        
        if not submit_response.ok:
            if submit_response.status_code == 429:
                return jsonify({"error": "Rate limit exceeded", "retry_after": 60}), 429
            return jsonify({"error": f"VirusTotal API error: {submit_response.status_code}"}), 500
        
        submit_data = submit_response.json()
        analysis_id = submit_data.get('data', {}).get('id')
        
        if not analysis_id:
            return jsonify({"error": "Failed to submit URL for analysis"}), 500
        
        # Poll for results (max 10 attempts, 2 seconds apart)
        max_attempts = 10
        for attempt in range(max_attempts):
            time.sleep(2)
            
            analysis_response = requests.get(
                f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                headers={'x-apikey': api_key},
                timeout=10
            )
            
            if not analysis_response.ok:
                continue
            
            analysis_data = analysis_response.json()
            status = analysis_data.get('data', {}).get('attributes', {}).get('status')
            
            if status == 'completed':
                stats = analysis_data['data']['attributes'].get('stats', {})
                return jsonify({
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "undetected": stats.get('undetected', 0),
                    "total": sum(stats.values())
                })
        
        # Timeout - analysis not completed
        return jsonify({"error": "Analysis timeout - try again later"}), 408
        
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timeout"}), 408
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Network error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Internal error: {str(e)}"}), 500


def main():
    """Start the web server."""
    global scanner
    
    import argparse
    parser = argparse.ArgumentParser(description="NeuroShield Malware Scanner Web Interface")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
    parser.add_argument("--model", default="xgboost_model.pkl", help="Model file")
    parser.add_argument("--scaler", default="scaler.pkl", help="Scaler file")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("NeuroShield Malware Scanner - Web Interface")
    print("=" * 50)
    
    # Initialize scanner
    print("Loading model...")
    scanner = MalwareScanner(args.model, args.scaler)
    print(f"Scanner ready! Features: {len(scanner.feature_names)}")
    
    print(f"\n🌐 Open your browser to: http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop\n")
    
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == '__main__':
    main()
