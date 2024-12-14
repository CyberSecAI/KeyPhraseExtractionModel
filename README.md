# Overview

The following is provided here:
1. A [dataset of 5216 samples](data_in/finetune_top25_KeyPhrase_WeaknessDescription_json.csv) 
2. Instructions to finetune the KeyPhraseExtraction model used to extract the Vulnerability Description KeyPhrases for published CVEs which are stored in https://github.com/CyberSecAI/cve_info.
3. Detail on the [Model Focus](#model-focus) with examples

Table of Contents
- [Overview](#overview)
- [Language Models](#language-models)
  - [Fine Tune Model](#fine-tune-model)
- [Dataset](#dataset)
- [Finetuning](#finetuning)
- [Model Focus](#model-focus)
  - [keyphrases](#keyphrases)
    - [Examples Of complex product, version, component](#examples-of-complex-product-version-component)
      - [CVE-2018-0004](#cve-2018-0004)
        - [Decscription](#decscription)
        - [Extracted KeyPhrases](#extracted-keyphrases)
      - [CVE-2018-0747](#cve-2018-0747)
        - [Description](#description)
        - [Extracted KeyPhrases](#extracted-keyphrases-1)
      - [CVE-2018-0008](#cve-2018-0008)
        - [Description](#description-1)
        - [Extracted KeyPhrases](#extracted-keyphrases-2)
  - [Succinct Over Verbose](#succinct-over-verbose)
    - [Examples](#examples)
      - [CVE-2018-0008](#cve-2018-0008-1)
        - [Description](#description-2)
        - [Extracted KeyPhrases](#extracted-keyphrases-3)
    - [Examples](#examples-1)
      - [CVE-2018-0016](#cve-2018-0016)
  
  


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
> 1. Do not currently support a System Prompt 
>     - a consideration if making the model accessible to others as a system prompt is one mitigation for prompt injection
> 2. Require OAuth to access and credentials must be renewed after 7 days. 
>     - a consideration if the model is to run continuously or for long periods.

# Dataset

A [dataset of 5216 samples](data_in/finetune_top25_KeyPhrase_WeaknessDescription_json.csv) is provided to finetune the model.

> [!TIP]  
> This dataset was built up from zero and validated using an LLM-as-a-judge in addition to manual review.
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

12. The loss curve reaches minimum at ~4.5 epochs.

# Model Focus
> [!TIP]
> "**There are no solutions. There are only trade-offs.**" Thomas Sowell

The section below highlights the consequence of these trade-offs.

## keyphrases
The primary focus of the schema, dataset, model is these [keyphrases](https://www.cve.org/Resources/General/Key-Details-Phrasing.pdf): 
- "rootcause",
- "weakness",
- "impact",
- "vector",
- "attacker",

and less so these:
- "product",
- "version",
- "component"

The product, version, component keyphrases:
1. Are arrays at the same level in the schema. A schema focused on product, version, component keyphrases might have nesting to handle the reality of many versions of products and associated components e.g.
   1. version 
      1. product
         1. component
2. will be extracted correctly for most cases, but won't be for more complex cases. See some examples below of more complex, and less common product, version, component information.


### Examples Of complex product, version, component
####  [CVE-2018-0004](https://nvd.nist.gov/vuln/detail/CVE-2018-0004)  

##### Decscription
A sustained sequence of different types of normal transit traffic can trigger a high CPU consumption denial of service condition in the Junos OS register and schedule software interrupt handler subsystem when a specific command is issued to the device. This affects one or more threads and conversely one or more running processes running on the system. Once this occurs, the high CPU event(s) affects either or both the forwarding and control plane. As a result of this condition the device can become inaccessible in either or both the control and forwarding plane and stops forwarding traffic until the device is rebooted. The issue will reoccur after reboot upon receiving further transit traffic. Score: 5.7 MEDIUM (CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H) For network designs utilizing layer 3 forwarding agents or other ARP through layer 3 technologies, the score is slightly higher. Score: 6.5 MEDIUM (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H) If the following entry exists in the RE message logs then this may indicate the issue is present. This entry may or may not appear when this issue occurs. /kernel: Expensive timeout(9) function: **Affected releases are Juniper Networks Junos OS: 12.1X46 versions prior to 12.1X46-D50; 12.3X48 versions prior to 12.3X48-D30; 12.3R versions prior to 12.3R12-S7; 14.1 versions prior to 14.1R8-S4, 14.1R9; 14.1X53 versions prior to 14.1X53-D30, 14.1X53-D34; 14.2 versions prior to 14.2R8; 15.1 versions prior to 15.1F6, 15.1R3; 15.1X49 versions prior to 15.1X49-D40; 15.1X53 versions prior to 15.1X53-D31, 15.1X53-D33, 15.1X53-D60. No other Juniper Networks products or platforms are affected by this issue.**

##### [Extracted KeyPhrases](https://github.com/CyberSecAI/cve_info/blob/main/2018/0xxx/CVE-2018-0004.json)
````

    "keyphrases": {
        "rootcause": "",
        "weakness": "",
        "impact": "high CPU consumption",
        "vector": "sustained sequence of different types of normal transit traffic",
        "attacker": "",
        "product": "Juniper Networks Junos OS",
        "version": "12.1X46, 12.3X48, 12.3R, 14.1, 14.1X53, 14.2, 15.1, 15.1X49, 15.1X53",
        "component": "register and schedule software interrupt handler subsystem"
````


#### [CVE-2018-0747](https://nvd.nist.gov/vuln/detail/CVE-2018-0747)

##### Description

**The Windows kernel in Windows 7 SP1, Windows 8.1 and RT 8.1, Windows Server 2008 SP2 and R2 SP1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703 and 1709, Windows Server 2016 and Windows Server, version 1709** allows an information disclosure vulnerability due to the way memory addresses are handled, aka "Windows Information Disclosure Vulnerability". This CVE ID is unique from CVE-2018-0745 and CVE-2018-0746.

##### Extracted KeyPhrases

````
{
    "rootcause": "",
    "weakness": "information disclosure",
    "impact": "",
    "vector": "",
    "attacker": "",
    "product": [
        "Windows 7 SP1",
        "Windows 8.1 and RT 8.1",
        "Windows Server 2008 SP2 and R2 SP1",
        "Windows Server 2012 and R2",
        "Windows 10 Gold",
        "1511",
        "1607",
        "1703 and 1709",
        "Windows Server 2016 and Windows Server"
    ],
    "version": [
        "Windows 7 SP1",
        "Windows 8.1",
        "Windows Server 2008 SP2",
        "Windows Server 2012",
        "Windows 10 Gold",
        "Windows Server 2016",
        "Windows Server"
    ],
    "component": "kernel"
}
````

#### [CVE-2018-0008](https://nvd.nist.gov/vuln/detail/CVE-2018-0008)

##### Description
"An unauthenticated root login may allow upon reboot when a commit script is used. A commit script allows a device administrator to execute certain instructions during commit, which is configured under the [system scripts commit] stanza. Certain commit scripts that work without a problem during normal commit may cause unexpected behavior upon reboot which can leave the system in a state where root CLI login is allowed without a password due to the system reverting to a safe mode authentication state. Lastly, only logging in physically to the console port as root, with no password, will work. **Affected releases are Juniper Networks Junos OS 12.1X46 versions prior to 12.1X46-D71 on SRX 12.3X48 versions prior to 12.3X48-D55 on SRX 14.1 versions prior to 14.1R9 14.1X53 versions prior to 14.1X53-D40 on QFX, EX 14.2 versions prior to 14.2R7-S9, 14.2R8 15.1 versions prior to 15.1F5-S7, 15.1F6-S8, 15.1R5-S6, 15.1R6 15.1X49 versions prior to 15.1X49-D110 on SRX 15.1X53 versions prior to 15.1X53-D232 on QFX5200/5110 15.1X53 versions prior to 15.1X53-D49, 15.1X53-D470 on NFX 15.1X53 versions prior to 15.1X53-D65 on QFX10K 16.1 versions prior to 16.1R2.** No other Juniper Networks products or platforms are affected by this issue."


##### Extracted KeyPhrases

https://github.com/CyberSecAI/cve_info/blob/main/2018/0xxx/CVE-2018-0008.json

````
        "product": [
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS",
            "Juniper Networks Junos OS"
        ],
        "version": [
            "12.1X46 versions prior to 12.1X46-D71",
            "12.3X48 versions prior to 12.3X48-D55",
            "14.1 versions prior to 14.1R9",
            "14.1X53 versions prior to 14.1X53-D40",
            "14.2 versions prior to 14.2R7-S9",
            "14.2R8",
            "15.1 versions prior to 15.1F5-S7",
            "15.1F6-S8",
            "15.1R5-S6",
            "15.1R6",
            "15.1X49 versions prior to 15.1X49-D110",
            "15.1X53 versions prior to 15.1X53-D232",
            "15.1X53 versions prior to 15.1X53-D49",
            "15.1X53 versions prior to 15.1X53-D470",
            "15.1X53 versions prior to 15.1X53-D65",
            "16.1 versions prior to 16.1R2"
        ],
        "component": ""
````

## Succinct Over Verbose



### Examples

#### [CVE-2018-0008](https://nvd.nist.gov/vuln/detail/CVE-2018-0008)

##### Description

> An **unauthenticated root login may allow upon reboot when a commit script is used**. A commit script allows a device administrator to execute certain instructions during commit, which is configured under the [system scripts commit] stanza. Certain commit scripts that work without a problem during normal commit may cause unexpected behavior upon reboot which can leave the system in a state where **root CLI login is allowed without a password** due to the system reverting to a safe mode authentication state. Lastly, only logging in physically to the console port as root, with no password, will work.

##### Extracted KeyPhrases

https://github.com/CyberSecAI/cve_info/blob/main/2018/0xxx/CVE-2018-0008.json
````
"rootcause": "unexpected behavior upon reboot",
"weakness": "",
"impact": "root CLI login without a password",
"vector": "commit script",
"attacker": "unauthenticated attacker",
````
E.g. "root CLI login is allowed without a password" is extracted as impact "root CLI login without a password"

### Examples

#### [CVE-2018-0016](https://nvd.nist.gov/vuln/detail/CVE-2018-0016)

Some CVE Descriptions include conditions in which the vulnerability does not apply. 

In general, this information is not extracted (by design).

e.g. https://github.com/CyberSecAI/cve_info/blob/main/2018/0xxx/CVE-2018-0016.json does not include this text

> Devices with without CLNS enabled are not vulnerable to this issue. Devices with IS-IS configured on the interface are not vulnerable to this issue unless CLNS routing is also enabled.




