import os
import csv
import random
from pathlib import Path

def get_random_entries_and_append(source_file, target_file, num_entries=500):
    """
    Randomly selects entries from source_file and appends them to target_file
    
    Args:
        source_file (str): Path to the source TSV file with 2025 CVEs
        target_file (str): Path to the target TSV file (with 2024 CVEs)
        num_entries (int): Number of random entries to select from source_file
    """
    # Read all entries from source file
    source_entries = []
    with open(source_file, 'r', encoding='utf-8') as infile:
        reader = csv.reader(infile, delimiter='\t')
        # Skip header row but save it
        header = next(reader)
        source_entries = list(reader)
    
    print(f"Found {len(source_entries)} entries in source file")
    
    # If we have fewer entries than requested, use all of them
    if len(source_entries) <= num_entries:
        selected_entries = source_entries
        print(f"Source file only has {len(source_entries)} entries, using all of them")
    else:
        # Randomly select entries
        selected_entries = random.sample(source_entries, num_entries)
        print(f"Randomly selected {num_entries} entries from source file")
    
    # Read header from target file to ensure compatibility
    with open(target_file, 'r', encoding='utf-8') as infile:
        reader = csv.reader(infile, delimiter='\t')
        target_header = next(reader)
        
        # Count existing entries in target file
        target_entry_count = sum(1 for _ in reader)
        
    print(f"Target file has {target_entry_count} existing entries")
        
    # Append selected entries to target file
    with open(target_file, 'a', encoding='utf-8', newline='') as outfile:
        writer = csv.writer(outfile, delimiter='\t')
        for entry in selected_entries:
            writer.writerow(entry)
            
    print(f"Successfully appended {len(selected_entries)} entries to {target_file}")
    print(f"Target file now has {target_entry_count + len(selected_entries)} total entries")

if __name__ == "__main__":
    # Get the project root directory
    project_root = Path(__file__).resolve().parent.parent
    
    # Define input and output file paths
    source_file = project_root / "new-data" / "nvd_cves_with_2025.tsv"
    target_file = project_root / "new-data" / "cti-vsp-only-2024.tsv"
    
    if not source_file.exists():
        print(f"Error: Source file {source_file} not found.")
    elif not target_file.exists():
        print(f"Error: Target file {target_file} not found.")
    else:
        print(f"Source file: {source_file}")
        print(f"Target file: {target_file}")
        get_random_entries_and_append(source_file, target_file, 500)