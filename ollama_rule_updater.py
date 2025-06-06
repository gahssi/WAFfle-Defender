import time
import os
import requests
import logging

logger = logging.getLogger('rule_updater')
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler('rule_updater.log')
fh.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

logger.addHandler(fh)

INJECTION_LOG_FILE = 'injection.tmp'
REGEX_RULES_FILE = 'regex_rules.txt'


INTERMEDIARY_SERVER_URL = "http://10.0.0.142:5000"  

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

def send_to_intermediary(injection_attempts):
    prompt = ROLE_PROMPT.format(injection_attempts=injection_attempts)
    try:
        payload = {"prompt": prompt}

        response = requests.post(INTERMEDIARY_SERVER_URL, json=payload)
        response.raise_for_status()  # Raise HTTP errors if any
        

        result = response.json()
        return result.get("response", "").strip()
    except Exception as e:
        logger.error(f"Error communicating with intermediary server: {e}")
        return None

def process_injections():
    try:
        if not os.path.exists(INJECTION_LOG_FILE):
            logger.info(f"No injection log file found: {INJECTION_LOG_FILE}")
            return

        with open(INJECTION_LOG_FILE, 'r') as f:
            injections = f.read().strip()

        if not injections:
            logger.info("No injection attempts to process.")
            return

        logger.info("Sending injection attempts to intermediary server for regex generation.")

        generated_regex = send_to_intermediary(injections)

        if generated_regex:
            with open(REGEX_RULES_FILE, 'a') as f:
                f.write(generated_regex + '\n')
            logger.info("Updated regex_rules.txt with new regex patterns.")

            open(INJECTION_LOG_FILE, 'w').close()
            logger.info("Cleared injection.tmp after processing.")
        else:
            logger.error("Failed to generate regex patterns from intermediary server.")

    except Exception as e:
        logger.error(f"Error processing injections: {e}")

def main():
    while True:
        time.sleep(30)
        process_injections()

if __name__ == '__main__':
    main()

