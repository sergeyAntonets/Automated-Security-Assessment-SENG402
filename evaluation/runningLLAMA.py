import os
# Configure PyTorch CUDA memory allocation for large models
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import torch
from huggingface_hub import login
from dotenv import load_dotenv

# Load environment variables and login to Hugging Face
load_dotenv()
login(os.getenv("LLAMATOKEN"))

# Model configuration
model_id = "meta-llama/Llama-3.1-8B-Instruct" 

# Use 4-bit quantization for efficient memory usage
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True, 
    bnb_4bit_compute_dtype=torch.float16
)

# Set the device to GPU if available, otherwise use CPU
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Load tokenizer and model from Hugging Face
# Model is loaded with quantization and device mapping
tokenizer = AutoTokenizer.from_pretrained(model_id)
model = AutoModelForCausalLM.from_pretrained(
    model_id,
    quantization_config=bnb_config,
    device_map="auto",
)

# Set pad token for tokenizer compatibility
tokenizer.pad_token = tokenizer.eos_token 


def llama_local_generate(sys_prompt, question, max_tokens, temperature, top_p, seed):
    torch.manual_seed(seed)
    
    # Build chat messages for the Llama chat template
    messages = [
        messages.append({"role": "system", "content": sys_prompt}),
        messages.append({"role": "user", "content": question}),
        ]

    # Format input for the model using the chat template
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
    generated_tokens = outputs[0][inputs_templated.shape[-1]:]
    result = tokenizer.decode(generated_tokens, skip_special_tokens=True)
    
    # Free up GPU memory
    del inputs_templated, outputs, generated_tokens 
    torch.cuda.empty_cache()
    
    return result.strip()