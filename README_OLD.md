# Automated Security Assessment

## About
This repository contains data and evaluation scripts for Automated Security Assessment, aimed to examine various LLMs in predicting CVSS v3.1 vector based on the vulnerability description. 

This codebase was built on top of [CTIBench](https://github.com/xashru/cti-bench) which is a benchmark to assess LLMs in a broad range of cyber threat intelligence (CTI) tasks.   

## Repository Structure

- `datasets/`  
  Contains CTI benchmark datasets in TSV format, including both large (for assessing LLMs) and small (for testing purposes) versions for 2024 and 2025 CVEs.

- `evaluation/`  
  Includes scripts and Jupyter notebooks for evaluating model performance, such as:
  - `evaluation.ipynb` and `model-prediction.ipynb`: Notebooks for running and analyzing model predictions.
  - `runningLLAMA.py`: Script for running LLAMA models locally.
  - `responses/`: Contains combined and individual model results for predicting CVSS vector.

- `result-outputs/`
  Stores output files and visualizations generated from evaluation scripts.

- `scripts/`  
  Utility scripts for dataset preparation and processing, such as combining results, extracting CVEs, and updating data prompts.


## References

- **CTIBench Paper:** [CTIBench: A Benchmark for Evaluating LLMs in Cyber Threat Intelligence](https://arxiv.org/abs/2406.07599), accepted at NeurIPS 2024.
- **Original repository:** [xashru/cti-bench](https://github.com/xashru/cti-bench)
