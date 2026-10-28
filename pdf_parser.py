import pdfplumber
import os
import re

def extract_text_from_pdf(pdf_path):
    text = ""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
    except Exception as e:
        print(f"Error reading {pdf_path}: {e}")
        return None
    return text

def extract_year_from_filename(filename):
    year_match = re.search(r'(20\d{2})', filename)
    if year_match:
        return int(year_match.group(1))
    return None

def extract_apt_group_from_filename(filename):
    apt_patterns = [
        r'(APT\d+)', r'(Lazarus)', r'(Cozy Bear)',
        r'(Fancy Bear)', r'(Kimsuky)', r'(APT29)',
        r'(APT28)', r'(APT41)', r'(APT10)', r'(APT33)'
    ]
    for pattern in apt_patterns:
        match = re.search(pattern, filename, re.IGNORECASE)
        if match:
            return match.group(1)
    return "Unknown"

def process_all_reports(reports_folder):
    results = []
    for filename in os.listdir(reports_folder):
        if filename.endswith('.pdf'):
            pdf_path = os.path.join(reports_folder, filename)
            print(f"Processing: {filename}")
            text = extract_text_from_pdf(pdf_path)
            year = extract_year_from_filename(filename)
            apt_group = extract_apt_group_from_filename(filename)
            if text:
                results.append({
                    'filename': filename,
                    'apt_group': apt_group,
                    'year': year,
                    'text': text,
                    'path': pdf_path
                })
                print(f"Extracted {len(text)} chars from {filename}")
    return results

if __name__ == "__main__":
    reports = process_all_reports('data/raw')
    print(f"\nTotal reports processed: {len(reports)}")
    if reports:
        print(f"APT Group: {reports[0]['apt_group']}")
        print(f"Year: {reports[0]['year']}")
        print(f"Text preview: {reports[0]['text'][:200]}")

