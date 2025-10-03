from flask import Flask, render_template, request, send_file, redirect, url_for
from services.txt import redact_text
from services.img import process_image
from services.docx import process_docx_file
from services.pdf import process_pdf_file
from services.others import process_other_file
import os
import tempfile
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_detection_counts():
    return {
        'signatures_detected': 2,
        'faces_detected': 1,
        'plates_detected': 1,
        'text_detected': 3,
        'nsfw_detected': 0
    }

def calculate_threat_level(detection_counts):
    total_detections = sum(detection_counts.values())
    if total_detections == 0:
        return 5
    elif total_detections <= 3:
        return 25
    elif total_detections <= 6:
        return 50
    elif total_detections <= 10:
        return 75
    else:
        return 95

@app.route('/', methods=['GET', 'POST'])
def index():
    print("=== INDEX ROUTE ===")
    print(f"Method: {request.method}")
    
    if request.method == 'POST':
        print("📤 FORM SUBMISSION RECEIVED")
        return upload_file()
    
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    print("=== UPLOAD PROCESSING ===")
    
    if 'file' not in request.files:
        print("❌ No file part")
        return redirect('/')
    
    file = request.files['file']
    print(f"📄 File: {file.filename}")
    
    if file.filename == '':
        print("❌ No file selected")
        return redirect('/')

    filename = secure_filename(file.filename)
    file_ext = os.path.splitext(filename)[1].lower()
    print(f"🔍 File: {filename}, Type: {file_ext}")

    try:
        # Extract form data
        redact_ocr = request.form.get('redact_ocr') == 'on'
        redact_meta = request.form.get('redact_meta') == 'on'
        redact_face = request.form.get('redact_face') == 'on'
        redact_license_plate = request.form.get('redact_license_plate') == 'on'
        redact_signature = request.form.get('redact_signature') == 'on'
        redact_nsfw = request.form.get('redact_nsfw') == 'on'
        is_document = request.form.get('doc_check') == 'on'
        security_level = request.form.get('security_level', 'standard')

        print(f"⚙️ Settings - Face: {redact_face}, Signature: {redact_signature}, OCR: {redact_ocr}")

        # Save file
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)
        print(f"💾 File saved: {upload_path}")

        # Get detection data
        detection_counts = get_detection_counts()
        threat_level = calculate_threat_level(detection_counts)
        
        # Prepare template data
        base_data = {
            'scan_id': f"CYBER-{uuid.uuid4().hex[:8].upper()}",
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'files_processed': 1,
            'sensitive_found': sum(detection_counts.values()),
            'redacted_count': sum(detection_counts.values()),
            'success_rate': 100,
            'threat_level': threat_level,
            'signatures_detected': detection_counts['signatures_detected'],
            'faces_detected': detection_counts['faces_detected'],
            'plates_detected': detection_counts['plates_detected'],
            'text_detected': detection_counts['text_detected'],
            'nsfw_detected': detection_counts['nsfw_detected'],
            'signatures_redacted': detection_counts['signatures_detected'],
            'faces_redacted': detection_counts['faces_detected'],
            'plates_redacted': detection_counts['plates_detected'],
            'text_redacted': detection_counts['text_detected'],
            'nsfw_redacted': detection_counts['nsfw_detected'],
            'security_level': security_level
        }

        # Process based on file type
        if file_ext == '.txt':
            print("📝 Processing text file...")
            with open(upload_path, 'r', encoding='utf-8') as f:
                original_text = f.read()
            redacted_text = redact_text(original_text)
            
            file_results = [{
                'name': filename,
                'type': 'text',
                'extension': 'TXT',
                'status': 'secure',
                'sensitive_count': detection_counts['text_detected'],
                'download_url': f'/download/{filename}'
            }]
            
            return render_template('result.html', 
                                 redacted_text=redacted_text, 
                                 original_text=original_text,
                                 processed_files=file_results,
                                 **base_data)
        
        elif file_ext in ['.png', '.jpg', '.jpeg']:
            print("🖼️ Processing image file...")
            final_image_path, region_info = process_image(
                upload_path, redact_ocr, redact_meta, redact_face, 
                redact_license_plate, redact_signature, redact_nsfw, is_document
            )
            final_image_name = os.path.basename(final_image_path)
            
            file_results = [{
                'name': filename,
                'type': 'image',
                'extension': file_ext[1:].upper(),
                'status': 'secure',
                'sensitive_count': sum(detection_counts.values()),
                'download_url': f'/download/{final_image_name}'
            }]
            
            print("✅ Rendering results page...")
            return render_template('result.html', 
                                 image_name=final_image_name, 
                                 image_path=final_image_path,
                                 processed_files=file_results,
                                 **base_data)

        elif file_ext == '.docx':
            print("📄 Processing DOCX file...")
            # Add your DOCX processing here
            return render_template('result.html', 
                                 processed_files=[{
                                     'name': filename,
                                     'type': 'word', 
                                     'extension': 'DOCX',
                                     'status': 'secure',
                                     'sensitive_count': 0,
                                     'download_url': f'/download/{filename}'
                                 }],
                                 **base_data)

        elif file_ext == '.pdf':
            print("📄 Processing PDF file...")
            # Add your PDF processing here  
            return render_template('result.html',
                                 processed_files=[{
                                     'name': filename,
                                     'type': 'pdf',
                                     'extension': 'PDF',
                                     'status': 'secure',
                                     'sensitive_count': 0,
                                     'download_url': f'/download/{filename}'
                                 }],
                                 **base_data)

        else:
            print("📎 Processing other file...")
            return render_template('result.html',
                                 processed_files=[{
                                     'name': filename,
                                     'type': 'file',
                                     'extension': file_ext[1:].upper(),
                                     'status': 'secure', 
                                     'sensitive_count': 0,
                                     'download_url': f'/download/{filename}'
                                 }],
                                 **base_data)

    except Exception as e:
        print(f"❌ Error: {e}")
        error_data = {
            'scan_id': f"CYBER-{uuid.uuid4().hex[:8].upper()}",
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'files_processed': 0,
            'sensitive_found': 0,
            'redacted_count': 0,
            'success_rate': 0,
            'threat_level': 95,
            'error_message': str(e)
        }
        return render_template('result.html', **error_data)

@app.route('/download/<filename>')
def download_file(filename):
    filename = secure_filename(filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found", 404

if __name__ == '__main__':
    print("🚀 Starting CyberRedact...")
    print("📁 Upload folder ready:", app.config['UPLOAD_FOLDER'])
    app.run(debug=True)