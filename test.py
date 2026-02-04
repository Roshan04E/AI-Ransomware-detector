from flask import Flask, render_template, request, redirect, url_for
import os
import asyncio
import time
from assets.VTIsMalicious import check_file
from assets.ransomware_dir_scanner import scan_single_file


# Initialize Flask app
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER




# Asynchronous placeholder for scan_file function
async def scan_file(filepath):
    # Mock scan functionality: replace this with your RBack module logic
    await asyncio.sleep(2)  # Simulate scanning delay

    vt_result = await check_file(filepath) #################UPDATE RESULT IN check_file function to return properly
    ml_result = await scan_single_file(filepath) ############ it returns true or false


    result = {
        "filename": os.path.basename(filepath),
        "hash": vt_result['hash'],
        "malicious_detections": vt_result["Malicious Detections"],
        "virustotal_result": vt_result['inference'],  
        "machine_learning_result": "Ransomware" if ml_result == True else "Benign"
    }
    return result






# Route for homepage
@app.route('/')
def index():
    return render_template('test.html')

# Route for file upload and scanning
@app.route('/upload', methods=['POST'])
async def upload_file():
    if 'file' not in request.files:
        return render_template('index.html', error="No file uploaded!")
    file = request.files['file']
    if file.filename == '':
        return render_template('index.html', error="No selected file!")
    print(request)
    
    # Save uploaded file
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    # Scan file and get results
    results = await scan_file(filepath)  # Return JSON-like object
    # Render the results page
    return render_template('testresult.html', results=results)


if __name__ == '__main__':
    app.run(debug=True)
