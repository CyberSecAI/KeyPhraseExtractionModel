# Overview

The following is provided here:
1. A [dataset of 5216 samples](data_in/finetune_top25_KeyPhrase_WeaknessDescription_json.csv) 
2. Instructions to finetune the KeyPhraseExtraction model used to extract the Vulnerability Description KeyPhrases for published CVEs which are stored in https://github.com/CyberSecAI/cve_info.

Table of Contents
- [Overview](#overview)
- [Language Models](#language-models)
  - [Fine Tune Model](#fine-tune-model)
- [Dataset](#dataset)
- [Finetuning](#finetuning)


# Language Models

> [!NOTE]  
> Google Gemini 2.0 Flash released https://blog.google/technology/google-deepmind/google-gemini-ai-update-december-2024/, Dec 11, 202

> [!NOTE]  
> Amazon has released its own suite of models per https://www.aboutamazon.com/news/aws/amazon-nova-artificial-intelligence-bedrock-aws Dec 3 2024
> 
> See https://aws.amazon.com/ai/generative-ai/nova/understanding/ for details.
> 

> [!TIP]  
>See https://artificialanalysis.ai/ for model comparisons.


## Fine Tune Model
Google Gemini Flash is used here.

Google https://aistudio.google.com/ is used as the model platform as it is the most accessible for new users, and is free to finetune.

> [!NOTE]  
> See https://cloud.google.com/ai/gemini for the difference between Google AIStudio and Google Vertex AI.

> [!WARNING] Fine tuned models in https://aistudio.google.com/ have limitations
> 1. Do not currently support a System Prompt (a consideration if making the model accessible to others as a system prompt is one mitigation for prompt injection)
> 2. Require OAuth to access and credentials must be renewed after 7 days. 

# Dataset

A [dataset of 5216 samples](data_in/finetune_top25_KeyPhrase_WeaknessDescription_json.csv) is provided to finetune the model.

> [!TIP]  
> This dataset was built up from zero and validated using an LLM-as-a-judge.
> 
> How this was done is very interesting and will be covered separately.

# Finetuning
1. Go to https://aistudio.google.com/tune
![Import](images/tune.png)

2. Click "Import" and select the [dataset of 5216 samples CSV](data_in/finetune_top25_KeyPhrase_WeaknessDescription_json.csv)
3. Select first column as Input 
4. Select second column as Output 
5. Click "Use first row as headers as the CSV has a heading row"

![Import](images/5216_samples.png)
6. Click "Import 5216 examples"
   
7. Give the model a name and description
8. Choose the base model
   > [!NOTE]  
   > Not all models are available for fine tuning.
![Import](images/import.png)

10. Click 'Advanced Settings'
![Import](images/choose_model.png)

11. The 'Advanced settings' can be left as is. 
    1.  The loss curve can be reviewed at the end of the finetuning.

12. Wait... approx 2.5 hours... for the finetuning to complete


![Import](images/tuned_results.png)

12.  The loss curve reaches minimum at ~4.5 epochs.

