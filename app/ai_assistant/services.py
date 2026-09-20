"""AI Assistant Services - Core AI agent logic.

Refactored from the standalone CLI script into reusable services.
Supports multiple AI providers (Gemini, OpenAI, Claude, DeepSeek).
All configuration is stored in a local config file that persists across restarts.
"""
import os
import json
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

# ─── Configuration ──────────────────────────────────────────────
SKILLS_DIR = os.path.join(os.path.dirname(__file__), 'skills')
os.makedirs(SKILLS_DIR, exist_ok=True)

# Config file for storing API keys and settings (persists across restarts)
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')


def get_config():
    """Load the AI Assistant config from the local config file."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
    except Exception as exc:
        logger.warning(f"Could not read config file: {exc}")
    return {}


def save_config(config_dict):
    """Save configuration to the local config file."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_dict, f, indent=2)
        return True
    except Exception as exc:
        logger.error(f"Could not save config file: {exc}")
        return False


# ─── Multi-Provider API Key Management ──────────────────────────

def get_api_key(provider_id=None):
    """Get the API key for a specific provider.

    Falls back to the old 'gemini_api_key' field for backward compatibility.
    If no provider_id is given, uses the currently selected provider.

    Args:
        provider_id: One of 'gemini', 'openai', 'claude', 'deepseek'.

    Returns:
        The API key string, or empty string if not set.
    """
    config = get_config()

    # Determine which provider to use
    if not provider_id:
        provider_id = config.get('selected_provider', 'gemini')

    # Try the new multi-provider key format first
    api_keys = config.get('api_keys', {})
    key = api_keys.get(provider_id, '')
    if key:
        return key

    # Backward compatibility: check old 'gemini_api_key' field
    if provider_id == 'gemini':
        old_key = config.get('gemini_api_key', '')
        if old_key:
            return old_key

    # Fall back to environment variable
    env_var = f'{provider_id.upper()}_API_KEY'
    return os.environ.get(env_var, '')


def set_api_key(provider_id, api_key):
    """Save an API key for a specific provider.

    Args:
        provider_id: One of 'gemini', 'openai', 'claude', 'deepseek'.
        api_key: The API key string.
    """
    config = get_config()
    if 'api_keys' not in config:
        config['api_keys'] = {}
    config['api_keys'][provider_id] = api_key.strip()
    # Also keep backward-compatible field
    if provider_id == 'gemini':
        config['gemini_api_key'] = api_key.strip()
    return save_config(config)


def get_selected_provider():
    """Get the currently selected provider ID."""
    config = get_config()
    return config.get('selected_provider', 'gemini')


def set_selected_provider(provider_id):
    """Set the currently selected provider ID."""
    config = get_config()
    config['selected_provider'] = provider_id
    return save_config(config)


def get_selected_model(provider_id=None):
    """Get the selected model for a provider."""
    config = get_config()
    if not provider_id:
        provider_id = config.get('selected_provider', 'gemini')
    models = config.get('selected_models', {})
    return models.get(provider_id, '')


def set_selected_model(provider_id, model):
    """Set the selected model for a provider."""
    config = get_config()
    if 'selected_models' not in config:
        config['selected_models'] = {}
    config['selected_models'][provider_id] = model
    return save_config(config)


# ─── Provider Factory ───────────────────────────────────────────

def _get_provider():
    """Get the currently configured AI provider instance.

    Reads the selected provider and its API key from config.
    Returns None if the provider is not configured.
    """
    from app.ai_assistant.providers import get_provider, PROVIDERS

    provider_id = get_selected_provider()
    api_key = get_api_key(provider_id)
    model = get_selected_model(provider_id)

    if not api_key:
        logger.warning(f"API key not set for provider: {provider_id}")
        return None

    # Validate the saved model against the provider's current model list.
    # If the saved model is no longer valid (e.g. Z.ai renamed a model),
    # fall back to the provider's default and update the config so the
    # next request doesn't fail with "Unknown Model".
    provider_info = PROVIDERS.get(provider_id)
    if provider_info:
        valid_models = provider_info.get('models', [])
        default_model = provider_info.get('default_model')
        if model and valid_models and model not in valid_models:
            logger.warning(
                f"Saved model '{model}' is not in the valid models list for "
                f"provider '{provider_id}'. Falling back to default "
                f"'{default_model}'."
            )
            model = default_model
            # Persist the corrected model so we don't warn every time
            set_selected_model(provider_id, default_model)
        elif not model:
            model = default_model

    return get_provider(provider_id, api_key, model if model else None)


# ─── Skills Management ──────────────────────────────────────────

def load_skills():
    """Load all skill files from the skills directory."""
    skills_context = ""
    if not os.path.exists(SKILLS_DIR):
        return skills_context
    for filename in sorted(os.listdir(SKILLS_DIR)):
        if filename.endswith(".txt"):
            skill_name = filename[:-4]
            filepath = os.path.join(SKILLS_DIR, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    skills_context += f"\n=== Skill: {skill_name} ===\n" + f.read() + "\n"
            except Exception as exc:
                logger.warning(f"Could not read skill file {filename}: {exc}")
    return skills_context


def save_skill(category, content):
    """Save or append a skill to the skills directory."""
    safe_category = ''.join(c for c in category if c.isalnum() or c == '_').lower()
    if not safe_category:
        return False
    filepath = os.path.join(SKILLS_DIR, f"{safe_category}.txt")
    try:
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(f"\n--- New Skill Entry ---\n{content}\n")
        logger.info(f"Saved skill: {safe_category}")
        return True
    except Exception as exc:
        logger.error(f"Failed to save skill {safe_category}: {exc}")
        return False


def list_skills():
    """Return a list of available skill names."""
    skills = []
    if not os.path.exists(SKILLS_DIR):
        return skills
    for filename in sorted(os.listdir(SKILLS_DIR)):
        if filename.endswith(".txt"):
            skills.append({
                'name': filename[:-4],
                'size': os.path.getsize(os.path.join(SKILLS_DIR, filename)),
            })
    return skills


def delete_skill(category):
    """Delete a skill file."""
    safe_category = ''.join(c for c in category if c.isalnum() or c == '_').lower()
    filepath = os.path.join(SKILLS_DIR, f"{safe_category}.txt")
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
            return True
    except Exception:
        pass
    return False


# ─── Crawler Agent ──────────────────────────────────────────────

def crawler_agent(url, cookie_str="", skills_text=""):
    """Crawls the target URL, extracts parameters, forms, inputs.

    Then runs the plugin-based Verification Engine to actively test
    every discovered parameter with real HTTP requests.

    Args:
        url: The target URL to crawl.
        cookie_str: Optional cookie string for authenticated sessions.
        skills_text: Optional loaded skills text (to determine which
                     verification modules to run).

    Returns:
        A string containing structured target data + verification results.
    """
    from app.ai_assistant.verification import run_verification, format_verification_results

    logger.info(f"Crawling target: {url}")
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
    }
    if cookie_str:
        headers["Cookie"] = cookie_str

    try:
        response = requests.get(url, headers=headers, timeout=15, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')

        parsed_url = urlparse(url)
        url_params = parse_qs(parsed_url.query)

        # ─── 1. Parameter Discovery ────────────────────────────
        forms_info = []
        all_injectable_params = []

        # Extract URL parameters
        for param_name in url_params:
            all_injectable_params.append({
                'name': param_name,
                'location': 'URL Parameter',
                'method': 'GET',
            })

        # Extract forms and inputs
        for i, form in enumerate(soup.find_all('form')):
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').upper()
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select', 'button']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    inputs.append({"name": input_name, "type": input_type})
                    # Add to injectable params (skip submit/button/hidden/token)
                    if input_type not in ('submit', 'button', 'hidden') and 'token' not in input_name.lower():
                        all_injectable_params.append({
                            'name': input_name,
                            'location': f'Form #{i+1} Input',
                            'method': form_method,
                        })
            forms_info.append({
                "form_index": i + 1,
                "action": form_action,
                "method": form_method,
                "inputs": inputs
            })

        # Build extracted data string
        extracted_data = f"Target URL: {url}\n"
        extracted_data += f"Response Status Code: {response.status_code}\n"
        extracted_data += f"--- Extracted URL Parameters ---\n{url_params if url_params else 'None'}\n\n"
        extracted_data += f"--- Extracted Forms & Inputs ---\n"
        if not forms_info:
            extracted_data += "No forms or input fields found on this page.\n"
        for form in forms_info:
            extracted_data += f"Form #{form['form_index']} | Action: {form['action']} | Method: {form['method']}\n"
            for inp in form['inputs']:
                extracted_data += f"  -> Input Name: {inp['name']} (Type: {inp['type']})\n"

        extracted_data += f"\n--- All Injectable Parameters ({len(all_injectable_params)}) ---\n"
        for p in all_injectable_params:
            extracted_data += f"  • {p['name']} (Location: {p['location']}, Method: {p['method']})\n"

        extracted_data += f"\n--- Partial HTML Context (First 2000 chars) ---\n{response.text[:2000]}\n"

        # ─── 2. Active Verification ────────────────────────────
        # Run the plugin-based verification engine on ALL discovered parameters
        logger.info(f"Starting Active Verification on {len(all_injectable_params)} parameters...")
        verification_results = run_verification(
            url=url,
            params=all_injectable_params,
            forms=forms_info,
            cookie_str=cookie_str,
            skills_text=skills_text or "",
        )

        # ─── 3. Format Verification Output ─────────────────────
        verification_text = format_verification_results(verification_results)
        extracted_data += f"\n{verification_text}"

        return extracted_data

    except Exception as e:
        logger.error(f"Error during crawling: {e}")
        return None


# ─── AI Agents (Provider-agnostic) ──────────────────────────────

def _ai_generate(prompt):
    """Call the currently selected AI provider to generate content.

    Args:
        prompt: The prompt string.

    Returns:
        The generated text, or an error message string.
    """
    provider = _get_provider()
    if provider is None:
        provider_id = get_selected_provider()
        return f"AI provider '{provider_id}' is not configured. Set the API key in the settings."
    return provider.generate_content(prompt)


def router_agent(target_data, skills):
    """Router Agent: determines which skill category matches the target best."""
    prompt = f"""
    You are the Router Agent in a Cyber Security Multi-Agent system.
    Your job is to look at the 'Target Data' (which contains URL, extracted inputs, forms, HTML context, AND Active Verification Results) and compare it with the 'Loaded Skill Memory'.

    IMPORTANT: The Target Data includes an 'ACTIVE VERIFICATION RESULTS' section.
    These results are from REAL HTTP testing, NOT predictions.
    You MUST prioritize verified findings (🟢 Verified) over any static analysis.

    Determine if any of the learned vulnerabilities are highly relevant to the inputs or forms found on the target page.

    Loaded Skill Memory:
    {skills}

    Target Data:
    {target_data}

    Respond in exactly one or two sentences explaining which skill category matches this target best and why.
    If there are Verified findings in the Active Verification Results, mention them explicitly.
    """
    return _ai_generate(prompt)


def analyzer_agent(target_data, selected_skill_context):
    """Analyzer Agent: analyzes the target for potential vulnerabilities."""
    prompt = f"""
    You are the Advanced Vulnerability Analyzer Agent.
    Analyze the following 'Target Data' utilizing the specific 'Skill Context' provided.

    CRITICAL RULES:
    1. The Target Data includes 'ACTIVE VERIFICATION RESULTS' from REAL HTTP testing.
    2. These verification results are the PRIMARY source of truth.
    3. If a vulnerability is marked as '🟢 Verified' in the verification results, it is CONFIRMED. Analyze how it can be exploited and provide detailed POC.
    4. If a vulnerability is marked as '🟡 Potential', note it as a potential issue that needs further investigation.
    5. If a vulnerability is marked as '🔴 Not Vulnerable', do NOT report it as a vulnerability.
    6. If there are NO verification results for a parameter, you may note it as 'Potential issue detected but not verified.'
    7. You must NEVER claim a vulnerability is confirmed without verification evidence.

    Skill Context (Learned Patterns):
    {selected_skill_context}

    Target Data (Current Target Info + Verification Results):
    {target_data}

    Provide a detailed security analysis based on the verification evidence.
    If no inputs or parameters are found, state that clearly.
    """
    return _ai_generate(prompt)


def triage_agent(analyzer_findings, target_data):
    """Triage Agent: verifies findings and produces a final report."""
    prompt = f"""
    You are the Senior Red Team Triage Expert.
    Your mission is to strictly review the 'Analyzer Findings' against the 'Target Data' AND the 'Active Verification Results'.

    CRITICAL RULES:
    1. The 'Active Verification Results' in the Target Data are from REAL HTTP testing.
    2. Only vulnerabilities marked as '🟢 Verified' in the verification results can be reported as 'Verified Vulnerability Found'.
    3. Vulnerabilities marked as '🟡 Potential' should be reported as 'Potential Vulnerability (Not Verified)'.
    4. Vulnerabilities marked as '🔴 Not Vulnerable' must NOT be reported.
    5. If there is NO verification evidence for a finding, you MUST state: 'Potential issue detected but not verified.'
    6. You must NEVER claim a vulnerability is confirmed without verification evidence from the Active Verification Results.
    7. Eliminate any hallucinations, assumptions, or predictions about things that do not exist in the data.

    Target Data (includes Verification Results):
    {target_data}

    Analyzer Findings:
    {analyzer_findings}

    Format your output as a professional Red Team Triage Report:
    1. Review of Analyzer Agent Findings (Validate or reject hypotheses based on verification evidence).
    2. Final Verified Report:
       - For verified findings: "✅ Verified Vulnerability Found" with exact parameters, POC payloads, and evidence.
       - For potential findings: "🟡 Potential Vulnerability (Not Verified)" with explanation.
       - If no findings: "No verified vulnerabilities found."
    3. Justification (reference the verification evidence).
    """
    return _ai_generate(prompt)


# ─── Orchestration ──────────────────────────────────────────────

def analyze_target(target_data):
    """Run the full multi-agent analysis pipeline."""
    available_skills = load_skills()
    if not available_skills.strip():
        return {
            'error': 'Skill memory is empty. Please train the agent first by adding a skill.',
            'router_result': '',
            'analyzer_result': '',
            'triage_result': '',
        }

    router_result = router_agent(target_data, available_skills)
    analyzer_result = analyzer_agent(target_data, available_skills)
    triage_result = triage_agent(analyzer_result, target_data)

    return {
        'error': None,
        'router_result': router_result,
        'analyzer_result': analyzer_result,
        'triage_result': triage_result,
    }


def run_scan(url, cookie_str="", custom_prompt=""):
    """Full scan pipeline: crawl + analyze."""
    # Load skills first so we can pass them to the crawler for active verification
    skills = load_skills()
    target_data = crawler_agent(url, cookie_str, skills_text=skills)
    if not target_data:
        return {
            'error': f'Could not retrieve target data from {url}',
            'target_data': '',
            'router_result': '',
            'analyzer_result': '',
            'triage_result': '',
        }

    results = analyze_target(target_data)
    if custom_prompt and not results.get('error'):
        results['custom_prompt'] = custom_prompt

    results['target_data'] = target_data
    return results
