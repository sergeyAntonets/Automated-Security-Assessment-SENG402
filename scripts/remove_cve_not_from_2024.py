import os
import csv
from pathlib import Path

def remove_cve_from_2023(input_file, output_file):
    """
    Reads a TSV file and writes a new file with only entries where URL contains 'CVE-2024'.
    
    Args:
        input_file (str): Path to the input TSV file
        output_file (str): Path to the output TSV file
    """
    # Create directories if they don't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    rows_kept = 0
    rows_removed = 0
    
    try:
        with open(input_file, 'r', encoding='utf-8') as infile, \
             open(output_file, 'w', newline='', encoding='utf-8') as outfile:
            
            # Create TSV reader and writer
            reader = csv.reader(infile, delimiter='\t')
            writer = csv.writer(outfile, delimiter='\t')
            
            # Write header row
            header = next(reader)
            writer.writerow(header)
            
            # Process each row
            for row in reader:
                if len(row) > 0 and 'cve-2024' in row[0].lower():
                    writer.writerow(row)
                    rows_kept += 1
                else:
                    rows_removed += 1
        
        print(f"Processing completed!")
        print(f"Entries kept: {rows_kept}")
        print(f"Entries removed: {rows_removed}")
        print(f"Output file created: {output_file}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Get the project root directory
    project_root = Path(__file__).resolve().parent.parent
    
    # Define input and output file paths specifically for cti-vsp.tsv
    input_file = project_root / "data" / "cti-vsp.tsv"
    output_file = project_root / "new-data" / "cti-vsp-only-2024.tsv"
    
    if not input_file.exists():
        print(f"Error: {input_file} not found.")
    else:
        print(f"\nProcessing: {input_file}")
        remove_cve_from_2023(input_file, output_file)