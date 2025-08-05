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

# LLAMA_CONFIG = {
#     "n_ctx": 8192,
#     "n_threads": 4,
#     "n_gpu_layers": -1,
#     "n_batch": 2048,
#     "verbose": False,
#     "use_mmap": False,
#     "use_mlock": False,
#     "repeat_penalty": 1.5,
#     "frequency_penalty": 0.7,
#     "presence_penalty": 0.7,
#     "last_n_tokens": 64,
#     "penalize_nl": True,
# }

minimal_config = {
    "n_ctx": 2048,
    "n_gpu_layers": 0,
    "verbose": True 
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
    **minimal_config
)
print("Model loaded successfully!")


def baron_local_generate(sys_prompt, question, max_tokens, temperature, top_p, seed, stop_sequences=None):
    llm.reset()
    
    full_prompt = f"{sys_prompt}\n\n{question}"
    
    # Default stop sequences if none provided
    if stop_sequences is None:
        stop_sequences = ["\n\n", "\nUser:", "### End", "Example:", "Instructions:", 
                          "CVE Description:", "Now analyze", "None", "User", "Root",
                          "Root.", "Root ", "User.", "User ", "None.", "None "]
    
    response = llm(
        full_prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p,
        repeat_penalty=1.5,
        frequency_penalty=0.7,
        presence_penalty=0.7,
        stop=stop_sequences,
        echo=False,
        seed=seed
    )
    
    return response['choices'][0]['text'].strip()