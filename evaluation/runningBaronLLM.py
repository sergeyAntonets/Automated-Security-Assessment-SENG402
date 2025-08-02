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
    "n_threads": 4,      # Number of CPU threads to use [3]
    "n_gpu_layers": -1,   # Number of layers to offload to GPU (0 = CPU only) [1, 4]
                         # Change to -1 for full GPU offload if you have enough VRAM (e.g., 8GB+ for this model) [3]
    "verbose": False,    # Set to False for cleaner output, True for detailed loading logs [5]
    "use_mmap": True,    # Use memory mapping for faster loading
    "use_mlock": True,   # Lock model in memory to prevent swapping
    "repeat_penalty": 1.1,  # Penalize repetitive tokens to prevent loops
    "top_k": 40,         # Limit token candidates for more focused responses
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


def baron_local_generate(sys_prompt, question, max_tokens, temperature, top_p, seed):
    # Reset the model's conversation state to ensure independence
    llm.reset()
    
    # Combine system prompt and question for BaronLLM
    full_prompt = f"{sys_prompt}\n\n{question}"
    
    # Generate response with improved parameters to prevent repetition
    response = llm(
        full_prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p,
        repeat_penalty=1.1,  # Penalize repetitive tokens
        stop=["\n\n", "\nUser:", "### End", "Example:", "Instructions:", "CVE Description:", "Now analyze", "None", "User", "Root"],
        echo=False,
        seed=seed
    )
    
    return response['choices'][0]['text'].strip()
