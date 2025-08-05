import requests
import pandas as pd
from openpyxl import load_workbook

# === CONFIGURATION ===
VT_API_KEY = 'API_KEY'  # <-- Replace this with your actual API key
FILE1_PATH = 'File1.xlsx'
FILE2_PATH = 'File2.xlsx'

def vt_lookup(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()
        attributes = data.get("data", {}).get("attributes", {})
        analysis = attributes.get("last_analysis_results", {})
        
        # Use the correct engine name: "Paloalto" (not "Palo Alto Networks")
        palo_alto_result = analysis.get("Paloalto", {})
        
        # Try both 'category' and 'result' fields
        verdict = palo_alto_result.get("category", palo_alto_result.get("result", "Not Found"))
        detected = attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0

        return {
            "sha256": attributes.get("sha256", "N/A"),
            "sha1": attributes.get("sha1", "N/A"),
            "md5": attributes.get("md5", "N/A"),
            "detected": detected,
            "palo_verdict": verdict
        }
    elif r.status_code == 404:
        return {"not_found": True}
    else:
        return {"error": True, "code": r.status_code}

def insert_into_table(ws, row_data):
    # Find the table headers (MD5, SHA1, SHA256) in the sheet
    header_row = None
    for row in range(1, ws.max_row + 1):
        if (ws[f"B{row}"].value == "MD5" and 
            ws[f"C{row}"].value == "SHA1" and 
            ws[f"D{row}"].value == "SHA256"):
            header_row = row
            break
    
    if header_row is None:
        print("Warning: Could not find table headers (MD5, SHA1, SHA256) in the sheet")
        return
    
    # Find the first empty row after the headers
    data_start_row = header_row + 1
    row = data_start_row
    while ws[f"B{row}"].value is not None and ws[f"B{row}"].value != "":
        row += 1
    
    # Insert data into the table
    ws[f"B{row}"] = row_data["md5"]
    ws[f"C{row}"] = row_data["sha1"] 
    ws[f"D{row}"] = row_data["sha256"]

def main():
    df = pd.read_excel(FILE2_PATH, header=None)
    hashes = df[0].dropna().tolist()

    wb = load_workbook(FILE1_PATH)
    
    # Access the three sheets
    sheet1 = wb['Sheet1']  # Malware covered by XDR (Palo Alto detects as malicious)
    sheet2 = wb['Sheet2']  # Not found or clean
    sheet3 = wb['Sheet3']  # Malware not covered by XDR (Palo Alto doesn't detect as malicious)

    for h in hashes:
        print(f"Checking: {h}")
        result = vt_lookup(h)

        if "error" in result:
            print(f"Error: {result['code']} for hash {h}")
            continue
        if "not_found" in result:
            # Hash not found on VirusTotal - goes to Sheet2
            insert_into_table(sheet2, {"md5": "N/A", "sha1": "N/A", "sha256": h})
            print(f"  → Sheet2: Not found on VirusTotal")
            continue

        if result["detected"]:
            verdict = result["palo_verdict"]
            if verdict != "Not Found" and verdict != "N/A":
                # Malware detected AND Palo Alto has a verdict - goes to Sheet3 (not covered by XDR)
                insert_into_table(sheet3, result)
                print(f"  → Sheet3: Malware not covered by XDR (Palo Alto verdict: {verdict})")
            else:
                # Malware detected BUT Palo Alto doesn't have a verdict - goes to Sheet1 (covered by XDR)
                insert_into_table(sheet1, result)
                print(f"  → Sheet1: Malware covered by XDR (Palo Alto verdict: {verdict})")
        else:
            # Clean hash (not detected as malware) - goes to Sheet2
            insert_into_table(sheet2, result)
            print(f"  → Sheet2: Clean hash")

    wb.save("File1_filled.xlsx")
    print("✅ Done. Output saved to File1_filled.xlsx")

if __name__ == "__main__":
    main()
