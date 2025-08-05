## Imports
from huggingface_hub import hf_hub_download
from llama_cpp import Llama

## Download the GGUF model
model_name = "AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF"
model_file = "baronllm-llama3.1-v1-q6_k.gguf"
model_path = hf_hub_download(model_name, filename=model_file)

## Instantiate model from downloaded file
llm = Llama(
    model_path=model_path,
    n_ctx=8192,  # Max context for Llama 3
    n_gpu_layers=-1,  # Offload all layers to GPU
    verbose=True,  # Enable verbose logging to see GPU usage
    use_mmap=True,  # Recommended for faster loading
)

## Generation kwargs
generation_kwargs = {
    "max_tokens": 1024 ,  # Much shorter response for one-sentence answer
    "stop": ["<|eot_id|>", "."],  # Use model's EOS token and period as stop tokens
    "echo": False,
    "temperature": 0.3,  # Lower temperature for more focused response
    "top_p": 0.9,
}
system_message = """
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

test_prompt = """
    Classify the vulnerability post-condition privilege as one of the following:
    - None: Attacker does not gain access to the system.  - User: Attacker gains
    user-level access (e.g., running code as a normal user, accessing user
    files).  - Root: Attacker gains full system or administrative access (e.g.,
    root privileges, complete control over the system or application).

    
    Vulnerability: A vulnerability has been found in Tenda AC10U
    15.03.06.49_multi_TDE01 and classified as critical. This vulnerability
    affects the function formSetVirtualSer. The manipulation of the argument
    list leads to stack-based buffer overflow. The attack can be initiated
    remotely. The exploit has been disclosed to the public and may be used.
    VDB-252130 is the identifier assigned to this vulnerability. NOTE: The
    vendor was contacted early about this disclosure but did not respond in any
    way.  CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

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


messages = [
    {"role": "system", "content": system_message},
    {"role": "user", "content": test_prompt}
]
## Run inference
print("Generating response...")
res = llm.create_chat_completion(
    messages,
    max_tokens=512,
    temperature=0.2,
    top_p=0.9,

)
## Print the generated text
print("\nModel Response:")
print(res["choices"][0]["message"]["content"])

## Explicitly clean up to avoid the exception
llm.close()