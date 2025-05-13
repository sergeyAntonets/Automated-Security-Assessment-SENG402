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
model_id = "meta-llama/Llama-3.1-8B-Instruct" # Updated model ID for the instruct version

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
)

# Tokenizer settings
tokenizer.pad_token = tokenizer.eos_token 

def llama_local_generate(sys_prompt, question, max_tokens, temperature, top_p, seed):
    torch.manual_seed(seed)
    
    # Construct messages for the chat template
    messages = []
    if sys_prompt and sys_prompt.strip(): # Add system prompt only if it's not empty
        messages.append({"role": "system", "content": sys_prompt})
    messages.append({"role": "user", "content": question})

    # Apply the chat template. add_generation_prompt=True is important.
    inputs_templated = tokenizer.apply_chat_template(
        messages,
        return_tensors="pt",
        add_generation_prompt=True
    ).to("cuda")
    
    with torch.no_grad():
        outputs = model.generate(
            input_ids=inputs_templated, # Use the templated input_ids
            max_new_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            do_sample=True,
            use_cache=True,
            pad_token_id=tokenizer.eos_token_id # Explicitly set pad_token_id
        )
    
    # Decode only the newly generated tokens
    # outputs[0] contains the full sequence (input + generated response)
    # inputs_templated.shape[-1] gives the length of the input sequence
    generated_tokens = outputs[0][inputs_templated.shape[-1]:]
    result = tokenizer.decode(generated_tokens, skip_special_tokens=True)
    
    del inputs_templated, outputs, generated_tokens # Adjusted variable names for clarity
    torch.cuda.empty_cache()
    
    return result.strip()