# Overview

Exact match, RegEx, Fuzzy matching are 
1. good, fast, cheap at finding matching phrases
2. deterministic
3. controllable
4. not good at finding semantically equivalent phrases

LLMs 
1. are good, relatively very slow, relatively more expensive, good at finding semantically matching phrases even if lexically they are very different e.g. [CVE-2022-36778](https://nvd.nist.gov/vuln/detail/CVE-2022-36778)
    >insert HTML / js code inside input how to get to the vulnerable input : Workers &gt; worker nickname &gt; inject in this input the code.

    is correctly interpreted as "cross-site scripting".

2. are non-deterministic by design
3. are not very controllable e.g. an LLM might (sometimes) exclude the additional part of 'Denial of Service' in (brackets) e.g.
   1. denial of service (CPU consumption)
   2. denial of service (traffic amplification)
   3. denial of service (crash)
   4. denial of service (100% CPU consumption)
4. can be used to 
   1. generate results
   2. review results (llm-as-a-judge)

Reviews can improve the quality of results
1. individual results 
2. results in aggregate 
   1. can reinforce good behavior e.g. more common terms can be used to feed a matcher.

The best overall results will be achieved with an **engineering** and a [**Compound System**](https://bair.berkeley.edu/blog/2024/02/18/compound-ai-systems/) that **combines the strengths of all these different approaches**.


>[!NOTE] 
> While [Prompt Engineering](https://cybersecai.github.io/prompt_engineering/prompt_engineering/) can improve results significantly, it is not used for the Bulk case of 250K CVEs.

