"""
Combine results from different models into a single TSV file for evaluation.
"""
import os
import csv

# Define file paths
base_dir = os.path.dirname(os.path.abspath(__file__))
gpt_file = os.path.join(base_dir, "SENG402_cti-vsp-only-2024-and-2025-BIG_gpt-4o-mini_results.txt")
gemini_file = os.path.join(base_dir, "SENG402_cti-vsp-only-2024-and-2025-BIG_gemini-2.0-flash_result.txt")
api_llama31_8b_file = os.path.join(base_dir, "SENG402_cti-vsp-only-2024-and-2025-BIG_api-llama3.1-8b_result.txt")
api_llama33_70b_file = os.path.join(base_dir, "SENG402_cti-vsp-only-2024-and-2025-BIG_api-llama3.3-70b_result.txt")
llama_local_instruct_file = os.path.join(base_dir, "SENG402_cti-vsp-only-2024-and-2025-BIG_llama-local_Llama-3.1-8b_INSTRUCT_result.txt")
source_tsv = os.path.join(base_dir, "cti-vsp-only-2024-and-2025-BIG.tsv")
output_file = os.path.join(base_dir, "MAD-results.tsv")

def read_results(filepath, add_prefix=False):
    """Read CVSS vectors from result files."""
    with open(filepath, 'r') as f:
        lines = f.readlines()

    # For formattin output file for evaluation code. 
    results = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("//"):
            if add_prefix and not line.startswith("CVSS:3.1/"):
                line = "CVSS:3.1/" + line
            results.append(line)
    return results

def read_gt_column(tsv_path):
    """Read the 'gt' column from the provided TSV file."""
    gt_values = []
    with open(tsv_path, newline='', encoding='utf-8') as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter='\t')
        for row in reader:
            gt_values.append(row['GT'])
    return gt_values

# Read results from each model
try:
    gt_results = read_gt_column(source_tsv)     
    gpt_results = read_results(gpt_file)
    gemini_results = read_results(gemini_file)
    api_llama31_results = read_results(api_llama31_8b_file)
    api_llama33_results = read_results(api_llama33_70b_file)
    llama_local_instruct_results = read_results(llama_local_instruct_file)

    print(f"Found {len(gt_results)} GT values")
    print(f"Found {len(gpt_results)} results from gpt")
    print(f"Found {len(gemini_results)} results from gemini")
    print(f"Found {len(api_llama31_results)} results from api-llama3.1")
    print(f"Found {len(api_llama33_results)} results from api-llama3.3")
    print(f"Found {len(llama_local_instruct_results)} results for llama local instruct")

    # Determine the maximum number of results
    max_results = max(len(gt_results), len(gpt_results), 
                      len(gemini_results), len(api_llama31_results), len(api_llama33_results), 
                      len(llama_local_instruct_results))

    # Pad shorter result lists with empty strings to match the longest one
    gt_results.extend([''] * (max_results - len(gt_results)))
    gpt_results.extend([''] * (max_results - len(gpt_results)))
    gemini_results.extend([''] * (max_results - len(gemini_results)))
    api_llama31_results.extend([''] * (max_results - len(api_llama31_results)))
    api_llama33_results.extend([''] * (max_results - len(api_llama33_results)))
    llama_local_instruct_results.extend([''] * (max_results - len(llama_local_instruct_results)))

    # Write the combined results to the output file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("GT\tllama-3.1-8B\tgpt-4o-mini\tgemini-2.0-flash\tapi-llama3.1-8b\tapi-llama3.3-70b\tllama-local\tllama-local-basic\tllama-local-instruct\n")
        for i in range(max_results):
            line = f"{gt_results[i]}\t{gpt_results[i]}\t{gemini_results[i]}\t{api_llama31_results[i]}\t{api_llama33_results[i]}\t{llama_local_instruct_results[i]}\n"
            f.write(line)

    print(f"Combined results written to {output_file}")

except FileNotFoundError as e:
    print(f"Error: {e}")
    print("Please make sure all result files are in the correct directory.")
except Exception as e:
    print(f"An error occurred: {e}")
