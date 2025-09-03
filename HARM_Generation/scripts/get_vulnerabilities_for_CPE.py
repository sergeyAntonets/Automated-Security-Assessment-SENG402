import requests
import os
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
        list: A list of CVE IDs (strings) for the latest number_of_CVEs, or an empty list if none found or error.
    """
    # Load environment variables from ../.env
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

        # Extract CVE IDs
        cves = []
        for vuln in data.get('vulnerabilities', []):
            cve_id = vuln.get('cve', {}).get('id')
            if cve_id:
                cves.append(cve_id)

        return cves[:number_of_CVEs]  # Ensure we return at most X

    except requests.RequestException as e:
        print(f"Error fetching CVEs: {e}")
        return []
    except KeyError as e:
        print(f"Error parsing response: {e}")
        return []




# Testing the function
print(get_latest_cves_for_cpe("cpe:2.3:o:microsoft:windows_10_21h2:-:*:*:*:*:*:arm64:*", 5))