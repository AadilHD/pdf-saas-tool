from flask import Flask, render_template, request, send_file
import os
from PyPDF2 import PdfReader, PdfWriter
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/merge-selected', methods=['POST'])
def merge_selected_pages():
    files = request.files.getlist('pdfs')
    page_ranges = request.form.getlist('ranges')

    if len(files) != len(page_ranges):
        return "Number of files and ranges must match.", 400

    writer = PdfWriter()

    for file, range_str in zip(files, page_ranges):
        start_str, end_str = range_str.split('-')
        start = int(start_str) - 1
        end = int(end_str)

        reader = PdfReader(file)
        for i in range(start, min(end, len(reader.pages))):
            writer.add_page(reader.pages[i])

    output_path = os.path.join(UPLOAD_FOLDER, "custom_merge.pdf")
    with open(output_path, "wb") as f:
        writer.write(f)

    return send_file(output_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)