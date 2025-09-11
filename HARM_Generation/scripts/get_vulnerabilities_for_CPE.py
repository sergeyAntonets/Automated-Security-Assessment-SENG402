import requests
import os
import csv
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import urllib.parse

def get_latest_cves_for_cpe(cpe_string, number_of_CVEs):
    """
    Fetches the number_of_CVEs latest CVEs for a given CPE string using the NVD API.

    Args:
        cpe_string (str): The CPE string, e.g., "cpe:2.3:o:microsoft:windows_10:-:21H2:*:*:*:*:*:*"
        number_of_CVEs(int): The number of latest CVEs to retrieve.

    Returns:
        list: A list of CVE dictionaries with detailed information for the latest number_of_CVEs, or an empty list if none found or error.
    """
     # Load environment variables from ../../.env
    load_dotenv('../.env')
    api_key = os.getenv('NVD_API_KEY')
    if not api_key:
        raise ValueError("NVD_API_KEY not found in .env file")


    # NVD API endpoint
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Parameters
    end_date = datetime.now(timezone.utc).replace(hour=23, minute=59, second=59, microsecond=0)
    start_date = (end_date - timedelta(days=119)).replace(hour=0, minute=0, second=0, microsecond=0)
    params = {
        'cpeName': cpe_string,
        'resultsPerPage': number_of_CVEs,
        'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%SZ'),
    }

    # Headers with API key
    headers = {
        'apiKey': api_key
    }

    # Print the request URL
    encoded_params = urllib.parse.urlencode(params)
    full_url = f"{url}?{encoded_params}"
    print(f"Request URL: {full_url}")

    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()  # Raise an error for bad status codes
        data = response.json()

        # Extract CVE details
        cves = []
        for vuln in data.get('vulnerabilities', []):
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id')
            
            if cve_id:
                # Get description (usually in English)
                descriptions = cve_data.get('descriptions', [])
                description = ""
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                # Get CVSS v3.1 vector string
                cvss_vector = ""
                metrics = cve_data.get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    for metric in metrics['cvssMetricV31']:
                        cvss_data = metric.get('cvssData', {})
                        cvss_vector = cvss_data.get('vectorString', '')
                        break
                
                # Extract vendor and product from CPE string
                cpe_parts = cpe_string.split(':')
                vendor = cpe_parts[3] if len(cpe_parts) > 3 else ""
                product = cpe_parts[4] if len(cpe_parts) > 4 else ""
                
                # Create CVE dictionary
                cve_dict = {
                    'ID': cve_id,
                    'CVSS_Vector': cvss_vector,
                    'Description': description.replace('\n', ' ').replace('\t', ' '),  # Clean up for TSV
                    'Vendor': vendor,
                    'Product': product
                }
                cves.append(cve_dict)

        return cves[:number_of_CVEs]  # Ensure we return at most X

    except requests.RequestException as e:
        print(f"Error fetching CVEs: {e}")
        return []
    except KeyError as e:
        print(f"Error parsing response: {e}")
        return []

def get_cve_filepath_for_cpe(cpe_string):
    """
    Generates the file path for the CVE TSV file based on the CPE string.
    """
    # Create a sanitized filename from the CPE string
    # Example: cpe:2.3:o:microsoft:windows_10 -> microsoft_windows_10.tsv
    filename_parts = cpe_string.split(':')[3:6] # vendor, product, version
    filename = "_".join(filename_parts).replace('*', '').replace(':-', '') + ".tsv"
    
    # Get the directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, "..","Vulnerabilities")
    os.makedirs(output_dir, exist_ok=True)
    return os.path.join(output_dir, filename)

def read_cves_from_tsv(filepath):
    """
    Reads a list of CVE dictionaries from a TSV file.
    """
    cves = []
    try:
        with open(filepath, 'r', newline='', encoding='utf-8') as f:
            # Adjust field names to match the output of get_latest_cves_for_cpe
            reader = csv.DictReader(f, fieldnames=['ID', 'CVSS_Vector', 'Description', 'Vendor', 'Product'], delimiter='\t')
            next(reader)  # Skip header row
            for row in reader:
                cves.append(row)
    except FileNotFoundError:
        print(f"File not found: {filepath}")
    except Exception as e:
        print(f"Error reading CVEs from {filepath}: {e}")
    return cves

def write_cves_to_tsv(cpe_string, cves):
    """
    Writes a list of CVE dictionaries for a given CPE to a TSV file.
    The filename is derived from the CPE string.
    """
    filepath = get_cve_filepath_for_cpe(cpe_string)

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter='\t')
        # Updated header with new columns
        writer.writerow(['cve_id', 'cvss_vector', 'description', 'vendor', 'product'])
        for cve in cves:
            writer.writerow([
                cve['ID'], 
                cve['CVSS_Vector'], 
                cve['Description'], 
                cve['Vendor'], 
                cve['Product']
            ])
    print(f"CVEs written to {filepath}")


def fetch_and_write_cves(cpe_string, number_of_CVEs):
    """
    Fetches the latest CVEs for a given CPE and writes them to a TSV file.
    """
    latest_cves = get_latest_cves_for_cpe(cpe_string, number_of_CVEs)
    if latest_cves:
        write_cves_to_tsv(cpe_string, latest_cves)
    return latest_cves

def fetch_CVEs_for_CPE(cpe_string, number_of_CVEs=10):
    """
    Checks if a CVE file exists for the given CPE. If not, it fetches
    the CVEs from the NVD API and creates the file.
    Returns the list of CVEs.
    """
    filepath = get_cve_filepath_for_cpe(cpe_string)
    if not os.path.exists(filepath):
        print(f"File {filepath} not found. Fetching CVEs...")
        return fetch_and_write_cves(cpe_string, number_of_CVEs)
    else:
        print(f"File {filepath} already exists.")
        return read_cves_from_tsv(filepath)



# # Testing the function
# cpe = "cpe:2.3:o:microsoft:windows_10_21h2:-:*:*:*:*:*:arm64:*"
# num_cves = 5
# fetch_and_write_cves(cpe, num_cves)