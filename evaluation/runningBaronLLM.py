from huggingface_hub import hf_hub_download, login
import os
from dotenv import load_dotenv
from llama_cpp import Llama

load_dotenv()

hf_token = os.getenv("LLAMATOKEN")
login(token=hf_token)

model_repo_id = "AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF"
model_filename = "baronllm-llama3.1-v1-q6_k.gguf"
local_dir = "./models" # Directory to save the model

LLAMA_CONFIG = {
    "n_ctx": 4096,       # Context length (increased for longer conversations) [1, 2]
    "n_threads": 8,      # Number of CPU threads to use [3]
    "n_gpu_layers": -1,   # Number of layers to offload to GPU (0 = CPU only) [1, 4]
                         # Change to -1 for full GPU offload if you have enough VRAM (e.g., 8GB+ for this model) [3]
    "verbose": False,    # Set to False for cleaner output, True for detailed loading logs [5]
    "use_mmap": True,    # Use memory mapping for faster loading
    "use_mlock": True,   # Lock model in memory to prevent swapping
}

os.makedirs(local_dir, exist_ok=True)

print(f"Downloading {model_filename} from {model_repo_id} to {local_dir}...")

model_path = hf_hub_download(
    repo_id=model_repo_id,
    filename=model_filename,
    local_dir=local_dir,
    local_dir_use_symlinks=False
)
print(f"Model downloaded to: {model_path}")


print("Loading model with llama_cpp...")
llm = Llama(
    model_path=model_path,
    **LLAMA_CONFIG
)
print("Model loaded successfully!")


def generate_response(prompt, max_tokens=1024, temperature=0.1, top_p=0.9):

    response = llm(
        prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p,
        stop=["\nUser:", "### End"], # Adjusted stop sequences based on BaronLLM's prompting guidelines [1]
        echo=False  # Don't include the prompt in the response [5]
    )
    return response['choices'][0]['text'].strip()


if __name__ == "__main__":
    test_prompt = """ROLE: Senior Pentester
OBJECTIVE: Analyze the following vulnerability:

CVE-2024-1234: A buffer overflow vulnerability exists in the network parsing function of XYZ software version 1.2.3. This could allow remote code execution.

What are the potential impacts and recommended mitigation strategies?"""

    print("\n" + "="*50)
    print("Testing BaronLLM model:")
    print("="*50)
    print(f"Prompt:\n{test_prompt}")
    print("\n" + "="*50)
    print("Response:")
    print("="*50)

    try:
        response = generate_response(test_prompt, max_tokens=500, temperature=0.7)
        print(response)
    except Exception as e:
        print(f"Error generating response: {e}")

    print("\n" + "="*50)