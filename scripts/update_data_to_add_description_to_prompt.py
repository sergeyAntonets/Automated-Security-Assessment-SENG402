"""
Used to fix a formatting issue in the 2025 CVE dataset where the description was not included in the prompt.
"""

import os
import csv
import sys
import re

def update_tsv_with_description(input_file_path):
    """
    Updates the TSV file by appending the description to the prompt for 2025 CVEs.
    
    Args:
        input_file_path: Path to the TSV file to update
    """
    # Create a backup of the original file
    backup_file = input_file_path + '.backup'
    
    try:
        # Read the TSV file
        rows = []
        with open(input_file_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f, delimiter='\t', quotechar='"', escapechar='\\')
            headers = next(reader)  # Get headers
            rows.append(headers)
            
            # Process each row
            for row in reader:
                if len(row) >= 4:  # Ensure we have URL, Description, Prompt, GT
                    url = row[0]
                    description = row[1]
                    prompt = row[2]
                    gt = row[3]
                    
                    # Check if this is a 2025 CVE
                    if 'CVE-2025' in url:
                        # Check if the description is already at the end of the prompt
                        if not prompt.strip().endswith(description.strip()):
                            # If the prompt ends with "CVE Description:" or has a place for it
                            if "CVE Description:" in prompt:
                                # Find where to add the description
                                pattern = r"CVE Description:(\s*)$"
                                if re.search(pattern, prompt):
                                    prompt = re.sub(pattern, f"CVE Description: {description}", prompt)
                                else:
                                    # Check if there's already text after "CVE Description:", don't modify
                                    cve_desc_pos = prompt.find("CVE Description:")
                                    if cve_desc_pos != -1 and len(prompt) > cve_desc_pos + 16:
                                        # There's already content after "CVE Description:"
                                        pass
                                    else:
                                        prompt = prompt.rstrip() + f" {description}"
                            else:
                                # If "CVE Description:" doesn't exist, append it with the description
                                prompt += f" CVE Description: {description}"
                    
                    row[2] = prompt
                rows.append(row)


        # Backing up the file as we are modifying file in place, safety incase errors 
        # Make a backup of the original file
        with open(backup_file, 'wb') as f_backup:
            with open(input_file_path, 'rb') as f_orig:
                f_backup.write(f_orig.read())
        
        # Write the updated content back to the file
        with open(input_file_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f, delimiter='\t', quotechar='"', escapechar='\\')
            writer.writerows(rows)
        
        print(f"Successfully updated {input_file_path}")
        print(f"A backup was created at {backup_file}")
    
    except Exception as e:
        print(f"Error updating file {input_file_path}: {e}")
        # If there was an error, try to restore from backup
        if os.path.exists(backup_file):
            print(f"Attempting to restore from backup...")
            try:
                with open(backup_file, 'rb') as f_backup:
                    with open(input_file_path, 'wb') as f:
                        f.write(f_backup.read())
                print("Restoration from backup completed.")
            except Exception as restore_error:
                print(f"Error restoring from backup: {restore_error}")

# Specify the filepath directly in the code
def main():
    # Using relative path to the 2025 BIG dataset
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    file_path = os.path.join(project_root, "new-data", "cti-vsp-only-2024-and-2025-BIG.tsv")
    
    
    print(f"Processing file: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return
    
    update_tsv_with_description(file_path)

if __name__ == "__main__":
    main()