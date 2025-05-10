import os
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import torch
from huggingface_hub import login
from dotenv import load_dotenv

# Load environment variables and login
load_dotenv()
login(os.getenv("LLAMATOKEN"))

# Model configuration
model_id = "meta-llama/Llama-3.1-8B"

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_compute_dtype=torch.float16
)

# Set the device to GPU if available, otherwise use CPU
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Load tokenizer and model
tokenizer = AutoTokenizer.from_pretrained(model_id)
model = AutoModelForCausalLM.from_pretrained(
    model_id,
    quantization_config=bnb_config,
    device_map="auto",
    torch_dtype=torch.float16,
)

# Tokenizer settings
tokenizer.pad_token = tokenizer.eos_token 

def llama_local_generate(sys_prompt, question, max_tokens, temperature, top_p):
    torch.manual_seed(seed)
    prompt = f"<|system|>\n{sys_prompt}\n<|user|>\n{question}\n<|assistant|>\n"

    inputs = tokenizer(prompt, return_tensors="pt", truncation=True).to("cuda")
    
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            do_sample=True,
            use_cache=True
        )
    
    result = tokenizer.decode(outputs[0], skip_special_tokens=True)
    
    # Remove the prompt from the decoded result to return only the assistant's reply
    result = result.split("<|assistant|>\n")[-1].strip()

    del inputs, outputs
    torch.cuda.empty_cache()
    
    return result