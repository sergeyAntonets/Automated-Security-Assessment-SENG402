import os
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from huggingface_hub import login
from dotenv import load_dotenv

# Load environment variables and login
load_dotenv()
login(os.getenv("LLAMATOKEN"))

# Model configuration
model_id = "meta-llama/Llama-3.1-8B"

# Set the device to GPU if available, otherwise use CPU
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Load tokenizer and model
tokenizer = AutoTokenizer.from_pretrained(model_id)
model = AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=torch.float16).to(device)

# Set pad_token_id to eos_token_id explicitly
tokenizer.pad_token = tokenizer.eos_token  
model.config.pad_token_id = tokenizer.eos_token_id  

def llama_local_generate(prompt, max_tokens, temperature, top_p):
    inputs = tokenizer(prompt, return_tensors="pt", padding=True, truncation=True).to(device)
    attention_mask = inputs.attention_mask.to(device)
    with torch.no_grad():
        outputs = model.generate(
            input_ids=inputs.input_ids,
            attention_mask=attention_mask,  
            max_new_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p
        )

    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    
    return tokenizer.decode(outputs[0], skip_special_tokens=True)
