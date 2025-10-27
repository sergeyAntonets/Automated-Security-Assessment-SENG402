# Automated Network Security Modelling 

## About 
This project was developed for SENG402 course at the University of Canterbury.  

This project was broken down into three main steps:

1. Predict the CVSS vector for a CVE based on its description using LLMs.

This part of the codebase was built on top of [CTIBench](https://github.com/xashru/cti-bench) which is a benchmark to assess LLMs in a broad range of cyber threat intelligence (CTI) tasks. 

- `research_and_testing/datasets/`  
  Contains CTI benchmark datasets in TSV format, including both large (for assessing LLMs) and small (for testing purposes) versions for 2024 and 2025 CVEs.

- `research_and_testing/evaluation/`  
  Includes scripts and Jupyter notebooks for evaluating model performance, such as:
  - `evaluation.ipynb` and `model-prediction.ipynb`: Notebooks for running and analyzing model predictions.
  - `runningLLAMA.py`: Script for running LLAMA models locally.
  - `responses/`: Contains combined and individual model results for predicting CVSS vector.

- `research_and_testing/scripts/`  
  Utility scripts for dataset preparation and processing, such as combining results, extracting CVEs, and updating data prompts.

2. Predicting vulnerability pre- and postconditions
For this part of the project we explored two approaches, LLM-based using BaronLLM and a supervised learning approach using SecureBERT.

- `research_and_testing/evaluation/LLM-predict-postcondition.ipynb`: A Jupyter notebook for predicting the postcondition of a vulnerability using BaronLLM.
- `research_and_testing/evaluation/SecureBERT Testing/secureBERT-postcondition-prediction.ipynb`: A Jupyter notebook that uses a fine-tuned SecureBERT model to classify the privilege required for a vulnerability, which helps in determining the postcondition.
- `research_and_testing/evaluation/SecureBERT Testing/securebert-privilege-classifier-final/`: Contains the final fine-tuned SecureBERT model for privilege classification.

3. Harm Generation and Attack Graph Modelling
This part of the project focuses on generating attack graphs and modeling network security based on the predicted vulnerabilities. This part of the code was based on code from [Automated Security Assessment for the Internet of Things](https://arxiv.org/abs/2109.04029).

This phase combines both previous parts and integrates them for automated HARM generation.

- `harm_generation/src/`: Contains the core Python scripts for building and analyzing attack graphs.
  - `Harm.py`: The main script that orchestrates the harm generation process.
  - `AttackGraph.py` & `AttackTree.py`: Scripts to construct and visualize attack graphs and trees.
  - `Network.py`, `Node.py`, `Topology.py`: Modules for creating and managing the network topology.
  - `Vulnerability.py` & `VulnerabilityNetwork.py`: Scripts for handling vulnerabilities and mapping them to the network.
  - `NetGen.py`: A utility for generating network topologies.

- `harm_generation/scripts/`: Includes helper scripts for the harm generation process.
  - `get_vulnerabilities_for_CPE.py`: A script to fetch vulnerability information for specific hardware or software configurations (CPEs).
  - `llm_utils.py`: Helper functions for prompting LLMs for CVSS vector prediction and pre- and postcondition extraction used in generating the HARM. 

- `harm_generation/Vulnerabilities/`: This directory stores vulnerability data in TSV format, which is used as input for the harm generation models.

