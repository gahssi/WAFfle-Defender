import os
import openai
from openai import OpenAI
import logging
import re

logger = logging.getLogger('rule_validator')
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler('rule_validator.log')
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

REGEX_RULES_FILE = 'regex_rules.txt'
SAFE_QUERIES_FILE = 'safe_queries.txt'

client = OpenAI(
    api_key = os.getenv("OPENAI_API_KEY")
)  

VALIDATION_PROMPT = r"""
We have the following regex rules for SQL injection detection:
{rules}

We have the following known safe queries:
{safe_queries}

Check if any of the given regex patterns cause false positives on the safe queries. If so, provide improved regex patterns that reduce false positives while still detecting malicious patterns. If all are fine, repeat them as is.

Only output the regex patterns, one per line.
"""

def load_rules():
    if not os.path.exists(REGEX_RULES_FILE):
        return []
    with open(REGEX_RULES_FILE, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def load_safe_queries():
    if not os.path.exists(SAFE_QUERIES_FILE):
        return []
    with open(SAFE_QUERIES_FILE, 'r') as f:
        return [q.strip() for q in f if q.strip()]

def validate_and_refine(rules, safe_queries):
    prompt = VALIDATION_PROMPT.format(rules="\n".join(rules), safe_queries="\n".join(safe_queries))
    try:
        response = client.chat.completions.create(
            model='gpt-4o',
            messages=[
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=400,
            n=1,
            stop=None,
        )
        output = response.choices[0].message.content.strip()
        return [line.strip() for line in output.split('\n') if line.strip()]
    except Exception as e:
        logger.error(f"Error communicating with OpenAI API for validation: {e}")
        return rules  # If error, revert to original rules
        
def main():
    rules = load_rules()
    if not rules:
        logger.info("No rules to validate.")
        return

    safe_queries = load_safe_queries()
    if not safe_queries:
        logger.info("No safe queries found, skipping validation.")
        return

    refined = validate_and_refine(rules, safe_queries)

    # Check refined rules syntax
    valid = []
    for pattern in refined:
        try:
            re.compile(pattern)
            valid.append(pattern)
        except re.error as e:
            logger.error(f"Invalid refined regex pattern '{pattern}': {e}")

    if valid:
        with open(REGEX_RULES_FILE, 'w') as f:
            for v in valid:
                f.write(v + '\n')
        logger.info("Refined and updated regex_rules.txt successfully.")
    else:
        logger.error("No valid rules after refinement. Keeping old rules as fallback.")
        # Revert to old rules
        with open(REGEX_RULES_FILE, 'w') as f:
            for r in rules:
                f.write(r + '\n')

if __name__ == '__main__':
    main()
