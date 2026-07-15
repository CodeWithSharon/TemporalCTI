import pandas as pd
import requests
import os
import time

# APT groups we want to focus on
TARGET_GROUPS = [
    'apt29', 'apt28', 'apt41', 'apt10', 'apt33',
    'lazarus', 'kimsuky', 'cozy bear', 'fancy bear',
    'turla', 'fin7', 'carbanak'
]

def is_relevant(filename, title):
    text = (filename + " " + title).lower()
    for group in TARGET_GROUPS:
        if group in text:
            return True
    return False

def download_reports():
    df = pd.read_csv('apt_reports/APTnotes.csv')
    print(f"Total reports in CSV: {len(df)}")
    
    os.makedirs('data/raw', exist_ok=True)
    
    downloaded = 0
    skipped = 0
    
    for _, row in df.iterrows():
        filename = str(row['Filename'])
        title = str(row['Title'])
        link = str(row['Link'])
        year = str(row['Year'])
        
        if not is_relevant(filename, title):
            skipped += 1
            continue
        
        pdf_name = f"{filename}_{year}.pdf"
        save_path = os.path.join('data/raw', pdf_name)
        
        if os.path.exists(save_path):
            print(f"Already exists: {pdf_name}")
            continue
        
        print(f"Downloading: {pdf_name}")
        try:
            response = requests.get(link, timeout=30)
            if response.status_code == 200:
                with open(save_path, 'wb') as f:
                    f.write(response.content)
                print(f"Saved: {pdf_name}")
                downloaded += 1
                time.sleep(1)
            else:
                print(f"Failed: {pdf_name} — Status {response.status_code}")
        except Exception as e:
            print(f"Error: {pdf_name} — {e}")
    
    print(f"\nDownloaded: {downloaded}")
    print(f"Skipped (not relevant): {skipped}")

if __name__ == "__main__":
    download_reports()
