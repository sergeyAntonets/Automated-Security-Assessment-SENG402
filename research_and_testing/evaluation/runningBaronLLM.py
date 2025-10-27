from huggingface_hub import hf_hub_download
from llama_cpp import Llama


model_name = "AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF"
model_file = "baronllm-llama3.1-v1-q6_k.gguf"
model_path = hf_hub_download(model_name, filename=model_file)

## Instantiate model from downloaded file
llm = Llama(
    model_path=model_path,
    n_ctx=2048,  
    n_gpu_layers=-1,  # Offload all layers to GPU
    verbose=False,  # Enable verbose logging to see GPU usage
    use_mmap=True,  # for faster loading
)


def baron_local_generate(sys_prompt, question, max_tokens, temperature, top_p, seed, stop_sequences=None):
    if stop_sequences is None:
        stop_sequences = ["<|eot_id|>"]

    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": question}
    ]
    
    response = llm.create_chat_completion(
        messages,
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p,
        stop=stop_sequences,
        seed=seed
    )
    
    return response['choices'][0]['message']['content'].strip()
