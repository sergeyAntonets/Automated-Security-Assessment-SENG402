"""
Get CVEs from NVD API by year and write to TSV file.
"""

import requests
import time
import os
from dotenv import load_dotenv
from pathlib import Path
import csv

# --- Configuration ---
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000  # Max allowed by NVD API 2.0
WAIT_TIME_SECONDS = 1  # Wait time between requests without API key

def get_cves_by_year_pattern(year, api_key):
    """
    Get CVEs that match a specific year in their ID.
    year: The year to filter CVEs by (e.g., "2025").
    api_key: Optional API key for NVD API to increase rate limits.
    """
    all_cves = []
    headers = {}
    wait_time = WAIT_TIME_SECONDS
    if api_key:
        headers['apiKey'] = api_key
        wait_time = 0.7  # Faster rate limit with API key
    
    params = {
        'keywordSearch': f'CVE-{year}',
        'resultsPerPage': RESULTS_PER_PAGE,
        'startIndex': 0
    }
    total_results = -1
    
    # Paginate through all API results
    while total_results == -1 or params['startIndex'] < total_results:
        if params['startIndex'] > 0:
            time.sleep(wait_time)
            
        try:
            response = requests.get(
                NVD_API_BASE_URL,
                params=params,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if total_results == -1:
                total_results = data.get('totalResults', 0)
                
            # Filter to only CVEs with exact year pattern (e.g., CVE-2025-XXXX)
            year_filtered_vulnerabilities = [vuln for vuln in vulnerabilities if f'CVE-{year}-' in vuln.get('cve', {}).get('id', '')]
            all_cves.extend(year_filtered_vulnerabilities)
            
            params['startIndex'] += len(vulnerabilities)
            
            if not vulnerabilities:
                break
                
        except Exception as e:
            time.sleep(wait_time)
            
    return all_cves

def write_cves_to_tsv(cves_data, filename="cves_output.tsv"):
    """
    Writes filtered CVE data to a TSV file (tab-separated values).
    Only includes CVEs with CVSS v3.1 vectors.

    """
    if not cves_data:
        return

    # Define CSV header
    header = ['URL', 'Description', 'Prompt', 'GT']

    # Define the standard prompt for all entries
    standard_prompt = """Analyze the following CVE description and calculate the CVSS v3.1 Base Score. Determine the values for each base metric: AV, AC, PR, UI, S, C, I, and A. Summarize each metric's value and provide the final CVSS v3.1 vector string.   Valid options for each metric are as follows: - **Attack Vector (AV)**: Network (N), Adjacent (A), Local (L), Physical (P) - **Attack Complexity (AC)**: Low (L), High (H) - **Privileges Required (PR)**: None (N), Low (L), High (H) - **User Interaction (UI)**: None (N), Required (R) - **Scope (S)**: Unchanged (U), Changed (C) - **Confidentiality (C)**: None (N), Low (L), High (H) - **Integrity (I)**: None (N), Low (L), High (H) - **Availability (A)**: None (N), Low (L), High (H)  Summarize each metric's value and provide the final CVSS v3.1 vector string. Ensure the final line of your response contains only the CVSS v3 Vector String in the following format:  Example format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  CVE Description:"""

    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, delimiter='\t')  # delimier or TSV
        writer.writerow(header)

        for vuln_data in cves_data:
            try:
                cve_info = vuln_data.get('cve', {})

                # 1. URL
                cve_id = cve_info.get('id', 'N/A')
                cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id != 'N/A' else 'N/A'

                # 2. Description
                english_description = 'N/A'
                descriptions = cve_info.get('descriptions', [])
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        english_description = desc.get('value', 'N/A')
                        break

                # Clean the description - replace newlines with spaces
                if english_description != 'N/A':
                    english_description = english_description.replace('\n', ' ').replace('\r', ' ')
                
                # 3. Prompt and append the description
                prompt = standard_prompt + f" {english_description}"

                # 4. GT (Vector String)
                vector_string = 'N/A'
                metrics = cve_info.get('metrics', {})
                  # Look for v3.1
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    vector_string = metrics['cvssMetricV31'][0].get('cvssData', {}).get('vectorString', 'N/A')
                
                # Skip entries without required data
                if vector_string == 'N/A' or english_description == 'N/A':
                    continue

                # Write the row
                writer.writerow([cve_url, english_description, prompt, vector_string])

            except Exception:
                pass

# --- Main Execution ---
# Load API Key from .env file
try:
    dotenv_path = Path(__file__).resolve().parent.parent / ".env"
    if dotenv_path.exists():
        load_dotenv(dotenv_path=dotenv_path)
    else:
        load_dotenv()  # Try the default path
except:
    pass  # Continue without API key if loading fails

NVD_API_KEY = os.getenv("NVD_API_KEY")
year = "2025"  # Target year for CVE collection

# Create the path to the new-data folder and ensure it exists
new_data_folder = Path(__file__).resolve().parent.parent / "new-data"
new_data_folder.mkdir(exist_ok=True)  # Create the folder if it doesn't exist

# Create the output file path in the new-data folder
output_file = new_data_folder / f"nvd_cves_with_{year}.tsv"

cves_data = get_cves_by_year_pattern(year, api_key=NVD_API_KEY)
write_cves_to_tsv(cves_data, filename=str(output_file))