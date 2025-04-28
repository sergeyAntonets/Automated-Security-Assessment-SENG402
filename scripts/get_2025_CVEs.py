import requests
from datetime import datetime, timedelta
import time
import json # For handling potential JSON decoding errors
import os
from dotenv import load_dotenv
from pathlib import Path
import csv # Import the csv library

# --- Configuration ---
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000  # Max allowed by NVD API 2.0
# NVD Rate Limits:
# Without API Key: 5 requests in a rolling 30-second window (~6 seconds apart)
# With API Key: 50 requests in a rolling 30-second window (~0.6 seconds apart)
# Set WAIT_TIME_SECONDS appropriately based on whether you use an API key.
# Using 1 second might be too fast without an API key. Start higher (e.g., 6) if needed.
WAIT_TIME_SECONDS = 1 # Increased default wait time for safety without API key
REQUEST_TIMEOUT = 30 # Seconds to wait for a response from the API

def get_cves_for_year(year, api_key): # Made api_key optional again
    """
    Get all CVEs for a specific year using direct requests to NVD API 2.0.

    Args:
        year (int): The year to fetch CVEs for.
        api_key (str, optional): Your NVD API key for higher rate limits. Defaults to None.

    Returns:
        list: A list of CVE dictionaries directly from the API response.
    """
    all_cves = []
    start_date = datetime(year, 1, 1)
    end_date = datetime(year, 12, 31)

    current_start_date = start_date
    total_fetched_for_year = 0

    headers = {}
    wait_time = WAIT_TIME_SECONDS # Default wait time
    if api_key:
        headers['apiKey'] = api_key
        wait_time = 0.7 # Can be faster with an API key (e.g., 0.7 seconds > 30/50)
        print(f"Using API Key. Setting wait time to {wait_time} seconds.")
    else:
        print(f"No API Key found. Using default wait time of {wait_time} seconds.")


    while current_start_date <= end_date:
        # Calculate the end of the 120-day window (max allowed by API)
        current_end_date = current_start_date + timedelta(days=119)
        if current_end_date > end_date:
            current_end_date = end_date

        print(f"Fetching CVEs from {current_start_date.date()} to {current_end_date.date()}...")

        # Format dates for the API query
        pub_start_str = current_start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" # Use ISO 8601 format with milliseconds and Z for UTC
        pub_end_str = current_end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


        start_index = 0
        total_results_for_window = -1 # Initialize to enter the pagination loop

        while total_results_for_window == -1 or start_index < total_results_for_window:
            params = {
                'pubStartDate': pub_start_str,
                'pubEndDate': pub_end_str,
                'resultsPerPage': RESULTS_PER_PAGE,
                'startIndex': start_index
            }

            # --- Add slight delay *before* the request to respect rate limits ---
            # Don't sleep on the very first request of the outer loop
            if start_index > 0 or current_start_date > datetime(year, 1, 1):
                 print(f"  Waiting {wait_time:.1f}s before next request...")
                 time.sleep(wait_time)

            try:
                # --- Make the API Request ---
                print(f"  Requesting page starting at index {start_index}...")
                response = requests.get(
                    NVD_API_BASE_URL,
                    params=params,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT
                )
                response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

                # --- Process the Response ---
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    print(f"  Error: Could not decode JSON response.")
                    # Decide how to handle: retry, skip, log? For now, break pagination loop for this window.
                    break # Break inner loop

                vulnerabilities = data.get('vulnerabilities', [])
                num_fetched_this_page = len(vulnerabilities)
                if total_results_for_window == -1: # Only get totalResults on the first page fetch for the window
                    total_results_for_window = data.get('totalResults', 0)

                if vulnerabilities:
                    all_cves.extend(vulnerabilities)
                    print(f"  Fetched {num_fetched_this_page} CVEs (Window total: {total_results_for_window}, Year total so far: {len(all_cves)})")
                else:
                    # Should ideally not happen if total_results_for_window > 0 and start_index < total_results_for_window
                    # but good to handle just in case the API behaves unexpectedly.
                    print("  No CVEs found on this page, but expected more. Breaking window fetch.")
                    break # Break inner loop

                # --- Prepare for Next Page ---
                start_index += num_fetched_this_page

                # No explicit sleep here, it's handled before the *next* request

            except requests.exceptions.Timeout:
                print(f"  Error: Request timed out after {REQUEST_TIMEOUT} seconds. Will retry after {WAIT_TIME_SECONDS}s delay...")
                time.sleep(WAIT_TIME_SECONDS) # Wait longer after a timeout
                # Keep start_index the same to retry the failed page request in the next loop iteration
                total_results_for_window = -1 # Reset to re-fetch total if needed

            except requests.exceptions.RequestException as e:
                print(f"  Error making API request: {e}")
                # If it's a rate limit error (403), wait longer. Otherwise, break.
                if response is not None and response.status_code == 403:
                     print(f"  Rate limit likely hit (403). Waiting {WAIT_TIME_SECONDS * 5}s before potentially retrying or moving on...")
                     time.sleep(WAIT_TIME_SECONDS * 5)
                     total_results_for_window = -1 # Reset to retry window safely
                else:
                     print(f"  Non-recoverable request error. Skipping rest of this time window.")
                     time.sleep(wait_time) # Still wait before next window
                     break # Break the inner pagination loop

            except Exception as e: # Catch unexpected errors during processing
                 print(f"  An unexpected error occurred: {e}")
                 print(f"  Skipping rest of this time window.")
                 break # Break the inner loop

        # --- Move to the next time window ---
        current_start_date = current_end_date + timedelta(days=1)

        # No explicit sleep here, handled at the start of the next window's request loop

    print(f"\nFinished fetching.")
    print(f"Total CVEs fetched for {year}: {len(all_cves)}")
    return all_cves

def write_cves_to_csv(cves_data, filename="cves_output.csv"):
    """
    Writes fetched CVE data to a CSV file.

    Args:
        cves_data (list): A list of CVE dictionaries from the NVD API.
        filename (str): The name of the CSV file to create.
    """
    print(f"\nWriting {len(cves_data)} CVEs to {filename}...")
    if not cves_data:
        print("No CVE data to write.")
        return

    # Define CSV header
    header = ['URL', 'Description', 'Prompt', 'GT']

    rows_written = 0
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)

        # Write the header
        writer.writerow(header)

        # Write the data rows
        for vuln_data in cves_data:
            try:
                cve_info = vuln_data.get('cve', {}) # Get the 'cve' dictionary

                # 1. URL
                cve_id = cve_info.get('id', 'N/A')
                cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id != 'N/A' else 'N/A'

                # 2. Description
                english_description = 'N/A'
                descriptions = cve_info.get('descriptions', [])
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        english_description = desc.get('value', 'N/A')
                        break # Found the English description

                # 3. Prompt (empty as requested)
                prompt = ''

                # 4. GT (Ground Truth - Vector String)
                vector_string = 'N/A'
                metrics = cve_info.get('metrics', {})
                # Prioritize CVSS v3.1, then v3.0, then v2
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    vector_string = metrics['cvssMetricV31'][0].get('cvssData', {}).get('vectorString', 'N/A')
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                     vector_string = metrics['cvssMetricV30'][0].get('cvssData', {}).get('vectorString', 'N/A')
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                     # V2 structure might be slightly different, check common patterns
                     cvss_v2_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                     if 'vectorString' in cvss_v2_data:
                        vector_string = cvss_v2_data.get('vectorString', 'N/A')
                     # Sometimes V2 vector is directly under the metric entry (older format?)
                     elif 'vectorString' in metrics['cvssMetricV2'][0]:
                         vector_string = metrics['cvssMetricV2'][0].get('vectorString', 'N/A')


                # Write the row
                writer.writerow([cve_url, english_description, prompt, vector_string])
                rows_written += 1

            except Exception as e:
                cve_id_err = vuln_data.get('cve', {}).get('id', 'UNKNOWN_ID')
                print(f"  Error processing CVE {cve_id_err} for CSV: {e}")

    print(f"Successfully wrote {rows_written} rows to {filename}")


# --- Main Execution ---

# Load API Key from .env file
try:
    dotenv_path = Path(__file__).resolve().parent.parent / ".env"
    if dotenv_path.exists():
        load_dotenv(dotenv_path=dotenv_path)
        print(f"Loaded .env file from: {dotenv_path}")
    else:
        print(f".env file not found at: {dotenv_path}")
except NameError:
    print("Could not determine script path automatically to find .env file.")
    dotenv_path = Path(".env")
    if dotenv_path.exists():
        load_dotenv(dotenv_path=dotenv_path)
        print(f"Loaded .env file from current directory.")

NVD_API_KEY = os.getenv("NVD_API_KEY")

target_year = 2025
output_csv_filename = f"nvd_cves_{target_year}.csv"

print(f"--- Starting CVE Fetch for {target_year} ---")
cves_data = get_cves_for_year(target_year, api_key=NVD_API_KEY)
print(f"--- Finished CVE Fetch for {target_year} ---")

if cves_data:
    write_cves_to_csv(cves_data, filename=output_csv_filename)
else:
    print("\nNo CVEs were fetched, skipping CSV write.")