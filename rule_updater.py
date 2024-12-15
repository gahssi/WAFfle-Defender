import os
from openai import OpenAI
import logging
import re

logger = logging.getLogger('rule_updater')
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler('rule_updater.log')
fh.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

logger.addHandler(fh)

INJECTION_LOG_FILE = 'injection.tmp'
REGEX_RULES_FILE = 'regex_rules.txt'

client = OpenAI(
    api_key = os.getenv("OPENAI_API_KEY")
)  

ROLE_PROMPT = r"""
You are a security engineer using a WAF to protect a web application with an input form against SQL injection attacks. You collected some HTTP queries which the WAF did not block and forwarded to the backend of the application. These queries are either safe inputs or are malicious SQL injections. Check for typical SQL injection attack patterns to verify if any of these queries are SQL injections. 

If you do not believe the queries show strong evidence of an SQL injection attack, leave your response blank. Otherwise, generate a regular expression that matches and detects the SQL injection attack pattern that you found in the queries. If different queries exhibit SQL injection attack patterns, generate multiple regular expressions in order to detect each of those injections. But, if the different queries are similar enough syntactically, you may generate one regular expression that appropriately matches and detects that kind of SQL injection attack pattern. Try to reduce the number of false positive matches as best as possible.

Your response should consist only of the required regular expressions. Do not include any other text or markdown code backticks in your response. The regular expressions should be formatted as standard regex syntax. Raw string notation is not needed and there is no need to escape " inside character class (['"]). If multiple regular expressions are required, each regular expression should be separated by a new line.

To illustrate, if I gave you the following query:
' or '1'='1';#

Your entire response could be:
(?:'|\b)(?:or\b|and\b).*?(?:--|;|#|'|")

As another example, if I gave you the following queries:
' or '1'='1';#
MIN(%20delay%20'0:20'%20-- for = "sql injection detection"

Your entire response could be:
(?:'|\b)(?:or\b|and\b).*?(?:--|;|#|'|")
(?i)(?:MIN\s*\(.*?\s*delay\s*['"]\d+:\d+['"]\s*--)


Finally, here is the collected query/queries:
{injection_attempts}
"""

def send_to_gpt(injection_attempts):
    prompt = ROLE_PROMPT.format(injection_attempts=injection_attempts)
    try:
        response = client.chat.completions.create(
            model='gpt-4o',
            messages=[
                {"role": "user", "content": prompt}
            ],
            max_tokens=200,
            temperature=0.2,
            n=1,
            stop=None,
        )
        generated_text = response.choices[0].message.content.strip()
        return generated_text
    except Exception as e:
        logger.error(f"Error communicating with OpenAI API: {e}")
        return None

def process_injections():
    if not os.path.exists(INJECTION_LOG_FILE):
        logger.info(f"No injection log file found: {INJECTION_LOG_FILE}")
        return False

    with open(INJECTION_LOG_FILE, 'r') as f:
        injections = f.read().strip()

    if not injections:
        logger.info("No injection attempts to process.")
        return False

    logger.info("Sending injection attempts to GPT for regex generation.")
    generated_regex = send_to_gpt(injections)

    if generated_regex:
        valid_patterns = []
        for pattern in generated_regex.strip().split('\n'):
            pattern = pattern.strip()
            if pattern:
                try:
                    re.compile(pattern)
                    valid_patterns.append(pattern)
                except re.error as e:
                    logger.error(f"Invalid regex pattern generated: '{pattern}': {e}")

        if valid_patterns:
            with open(REGEX_RULES_FILE, 'a') as f:
                for regex in valid_patterns:
                    f.write(regex + '\n')
            logger.info("Updated regex_rules.txt with new regex patterns.")

            open(INJECTION_LOG_FILE, 'w').close()
            logger.info("Cleared injection.tmp after processing.")
            return True
        else:
            logger.error("No valid regex patterns generated.")
            return False
    else:
        logger.error("Failed to generate regex patterns from GPT.")
        return False
