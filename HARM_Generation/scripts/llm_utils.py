"""
LLM utilities for postcondition classification.
Extracted from LLM-predict-postcondition.ipynb for use in the Vulnerability class.
"""

import re


# System prompt for postcondition classification using both description and CVSS
POSTCONDITION_SYSTEM_PROMPT_BOTH = """
You are a cybersecurity vulnerability classification expert. Your task is to
determine the post-condition privilege level after successful exploitation.

POST-CONDITION PRIVILEGE LEVEL DEFINITIONS: - None: Attacker does not gain
access to the system. No execution privileges are obtained.  - User:
Attacker gains user-level access (e.g., running code as a normal user,
accessing user files, limited privileges).  - Root: Attacker gains full
system or administrative access (e.g., root privileges, complete control
over the system or application, administrator rights).

CLASSIFICATION INSTRUCTIONS: 1. Analyze both the CVE description and CVSS
vector 2. Provide a brief justification 3. End your
response with: ##POSTCONDITION [classification] 4. The classification must
be EXACTLY one of: None, User, Root
"""

# User prompt template for both description and CVSS
POSTCONDITION_PROMPT_BOTH = """
Classify the vulnerability post-condition privilege as one of the following:
- None: Attacker does not gain access to the system.  - User: Attacker gains
user-level access (e.g., running code as a normal user, accessing user
files).  - Root: Attacker gains full system or administrative access (e.g.,
root privileges, complete control over the system or application).

Vulnerability: {description}
CVSS Vector: {cvss}

Examples: Example 1: Vulnerability: XSS vulnerability allows stealing user
session cookies.  CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
Classification: User Justification: Attacker gains access to user session
data but not system control.

Example 2: Vulnerability: SQL injection allows database manipulation.  CVSS
Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H Classification: User
Justification: Attacker gains database access but not full system control.

Now classify the given vulnerability: Justification: [Your justification]
##POSTCONDITION [Your classification: None, User, or Root]
"""


# System prompt for predicting the CVSS vector extraction
CVSS_VECTOR_SYSTEM_PROMPT = """ 
You are a cybersecurity expert specializing in cyberthreat intelligence.
"""

# User prompt template for CVSS vector extraction
CVSS_VECTOR_PROMPT = """ 
Analyze the following CVE description and calculate the CVSS v3.1 Base Score.
Determine the values for each base metric: AV, AC, PR, UI, S, C, I, and A.
Summarize each metric’s value and provide the final CVSS v3.1 vector string.
Valid options for each metric are as follows: - Attack Vector (AV): Network (N),
Adjacent (A), Local (L), Physical (P) - Attack Complexity (AC): Low (L), High
(H) - Privileges Required (PR): None (N), Low (L), High (H) - User Interaction
(UI): None (N), Required (R) - Scope (S): Unchanged (U), Changed (C) -
Confidentiality (C): None (N), Low (L), High (H) - Integrity (I): None (N), Low
(L), High (H) - Availability (A): None (N), Low (L), High (H) Summarize each
metric’s value and provide the final CVSS v3.1 vector string. Ensure the final
line of your response contains only the CVSS v3 Vector String in the following
format: Example format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H CVE
Description:
"""

# LLM generation parameters
DEFAULT_TEMPERATURE = 0.3
DEFAULT_TOP_P = 0.9
DEFAULT_SEED = 42
DEFAULT_MAX_TOKENS = 256


def format_post_condition(text):
    """
    Extract post-condition privilege classification from LLM response text.
    Returns the last valid classification found and whether extraction was successful.
    """
    # Define the regex pattern for matching privilege classification
    privilege_pattern = r'^(None|User|Root)[.:\s]*$'
    
    # Split the text into lines (from bottom up) and search for a matching line
    lines = text.strip().splitlines()
    for line in reversed(lines):
        line = line.strip()
        if re.match(privilege_pattern, line):
            # Extract just the classification word
            match = re.match(r'^(None|User|Root)', line)
            if match:
                return match.group(1), True
    
    # If no exact match found, look for the classification word anywhere in the text
    text_reversed = text[::-1]
    for word in ["tooR", "resU", "enoN"]:  # Reversed words
        if word in text_reversed:
            pos = text_reversed.find(word)
            return word[::-1], True  # Reverse back to original
    
    # If still not found, return the entire text and mark as failed
    return text, False


def generate_postcondition_llm(cvss_vector, description, llm_function, 
                             temperature=DEFAULT_TEMPERATURE, 
                             top_p=DEFAULT_TOP_P, 
                             seed=DEFAULT_SEED, 
                             max_tokens=DEFAULT_MAX_TOKENS):
    """
    Generate postcondition using LLM based on CVSS vector and description.
    
    :param cvss_vector: CVSS vector string
    :param description: CVE description
    :param llm_function: Function to call LLM (e.g., baron_local_generate)
    :param temperature: LLM temperature parameter
    :param top_p: LLM top_p parameter
    :param seed: LLM seed parameter
    :param max_tokens: Maximum tokens for LLM response
    :returns: postcondition string ('None', 'User', or 'Root')
    """
    try:
        # Use both description and CVSS vector
        system_prompt = POSTCONDITION_SYSTEM_PROMPT_BOTH
        user_prompt = POSTCONDITION_PROMPT_BOTH.format(description=description, cvss=cvss_vector)
        
        # Call the LLM
        response = llm_function(
            system_prompt, 
            user_prompt, 
            max_tokens=max_tokens, 
            temperature=temperature, 
            top_p=top_p, 
            seed=seed
        )
        
        # Extract classification from response
        postcondition, success = format_post_condition(response)
        
        if success:
            return postcondition
        else:
            print(f"Warning: Failed to extract postcondition from LLM response. Using 'User' as default.")
            print(f"Raw response: {response}")
            return 'User'
            
    except Exception as e:
        print(f"LLM generation failed: {e}")
        return 'User'  # Default fallback




def format_cvss_vector(text):
    """
    Extract CVSS v3.1 vector string from LLM response text.
    Returns the last valid CVSS vector found and whether extraction was successful.
    """
    # Define the regex pattern for CVSS v3.1 vector string format
    cvss_pattern = r'CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]'
    
    # Find all matches in the text
    matches = re.findall(cvss_pattern, text)

    # Return the last match if any match is found
    if matches:
        return matches[-1], True
    
    # Fallback for format without 'CVSS:3.1/' prefix
    cvss_pattern_no_prefix = r'AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]'
    matches = re.findall(cvss_pattern_no_prefix, text)
    if matches:
        return f"CVSS:3.1/{matches[-1]}", True

    # Return original text if no valid CVSS vector found
    return text, False


def predict_cvss_vector(description, llm_function,
                        temperature=DEFAULT_TEMPERATURE,
                        top_p=DEFAULT_TOP_P,
                        seed=DEFAULT_SEED,
                        max_tokens=DEFAULT_MAX_TOKENS):
    """
    Predict CVSS vector using LLM based on a CVE description.

    :param description: CVE description
    :param llm_function: Function to call LLM (e.g., llama_local_generate)
    :param temperature: LLM temperature parameter
    :param top_p: LLM top_p parameter
    :param seed: LLM seed parameter
    :param max_tokens: Maximum tokens for LLM response
    :returns: CVSS vector string
    """
    try:
        system_prompt = CVSS_VECTOR_SYSTEM_PROMPT
        user_prompt = CVSS_VECTOR_PROMPT + description

        # Call the LLM
        response = llm_function(
            system_prompt,
            user_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            seed=seed
        )

        # Extract CVSS vector from response
        cvss_vector, success = format_cvss_vector(response)

        if success:
            return cvss_vector
        else:
            print(f"Warning: Failed to extract CVSS vector from LLM response. Returning raw response.")
            print(f"Raw response: {response}")
            return response

    except Exception as e:
        print(f"LLM generation for CVSS vector failed: {e}")
        return 'Error'  # Default fallback