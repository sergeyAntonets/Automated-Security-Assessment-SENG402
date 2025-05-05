from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import torch
from huggingface_hub import login
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

login(os.getenv("LLAMATOKEN"))


model_id = "meta-llama/Llama-3.1-8B"  # Accept the license on Hugging Face!


# Load tokenizer and model
tokenizer = AutoTokenizer.from_pretrained(model_id, token=True)
model = AutoModelForCausalLM.from_pretrained(model_id, token=True)


def llama_local_generate(prompt, max_tokens=256, temperature=0.7, top_p=0.9):
    input_ids = tokenizer(prompt, return_tensors="pt").input_ids.to(model.device)
    output = model.generate(
        input_ids=input_ids,
        max_new_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p
    )
    return tokenizer.decode(output[0], skip_special_tokens=True)
