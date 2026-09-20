"""Verification Engine - Plugin-based active vulnerability verification.

This engine performs real HTTP testing to verify vulnerabilities BEFORE
sending data to the AI. The AI uses this evidence as the primary source of truth.

Status indicators:
  🟢 Verified → Vulnerability proven with evidence.
  🟡 Potential → Indicators found but no definitive proof.
  🔵 Not Tested → Could not be tested.
  🔴 Not Vulnerable → Tested and no vulnerability detected.
"""
from app.ai_assistant.verification.base_module import BaseVerificationModule
from app.ai_assistant.verification.xss_module import XSSModule
from app.ai_assistant.verification.sqli_module import SQLiModule
from app.ai_assistant.verification.ssti_module import SSTIModule
from app.ai_assistant.verification.cmdi_module import CmdInjectionModule
from app.ai_assistant.verification.lfi_module import LFIModule
from app.ai_assistant.verification.redirect_module import OpenRedirectModule
from app.ai_assistant.verification.ssrf_module import SSRFModule
from app.ai_assistant.verification.idor_module import IDORModule
from app.ai_assistant.verification.xxe_module import XXEModule
from app.ai_assistant.verification.csrf_module import CSRFModule
from app.ai_assistant.verification.graphql_module import GraphQLModule
from app.ai_assistant.verification.jwt_module import JWTModule

import logging

logger = logging.getLogger(__name__)

# Plugin Registry - each module provides payload generation, verification, and evidence collection
VERIFICATION_MODULES = {
    'xss': XSSModule,
    'sqli': SQLiModule,
    'ssti': SSTIModule,
    'command_injection': CmdInjectionModule,
    'lfi': LFIModule,
    'open_redirect': OpenRedirectModule,
    'ssrf': SSRFModule,
    'idor': IDORModule,
    'xxe': XXEModule,
    'csrf': CSRFModule,
    'graphql': GraphQLModule,
    'jwt': JWTModule,
}


def get_available_modules():
    """Return a list of available verification module names."""
    return list(VERIFICATION_MODULES.keys())


def run_verification(url, params, forms, cookie_str="", skills_text=""):
    """Run all applicable verification modules against discovered parameters.

    Args:
        url: The target URL.
        params: List of dicts: [{'name': 'id', 'location': 'URL', 'method': 'GET'}, ...]
        forms: List of form dicts from crawler.
        cookie_str: Optional cookie string.
        skills_text: Loaded skills text (to determine which modules to run).

    Returns:
        A list of structured verification result dicts.
    """
    results = []

    # Determine which modules to run based on skills
    skills_lower = (skills_text or "").lower()
    modules_to_run = []

    for mod_name, mod_class in VERIFICATION_MODULES.items():
        # Run module if its keyword is in skills, or if no skills loaded (run all)
        if not skills_text.strip() or mod_name in skills_lower or mod_class.KEYWORD in skills_lower:
            modules_to_run.append((mod_name, mod_class))

    # If no specific matches, run all modules
    if not modules_to_run and not skills_text.strip():
        modules_to_run = list(VERIFICATION_MODULES.items())

    logger.info(f"Verification Engine: Running {len(modules_to_run)} modules on {len(params)} parameters")

    # Collect all injectable parameters
    all_targets = []
    for p in params:
        all_targets.append({
            'name': p['name'],
            'location': p.get('location', 'URL'),
            'method': p.get('method', 'GET'),
        })

    # Run each module against each parameter
    for mod_name, mod_class in modules_to_run:
        module = mod_class(url=url, cookie_str=cookie_str)
        for target in all_targets:
            try:
                result = module.verify(target['name'], target['location'], target['method'])
                if result:
                    results.append(result)
            except Exception as exc:
                logger.warning(f"Verification error in {mod_name} for param '{target['name']}': {exc}")

    return results


def format_verification_results(results):
    """Format verification results into a structured text block for the AI.

    Args:
        results: List of result dicts from run_verification().

    Returns:
        A formatted string block.
    """
    if not results:
        return (
            "--- ACTIVE VERIFICATION RESULTS ---\n"
            "No vulnerabilities were verified through active HTTP testing.\n"
            "The AI must rely on static analysis only.\n"
            "If the AI identifies a potential issue, it MUST state: "
            "'Potential issue detected but not verified.'\n"
        )

    output = f"--- ACTIVE VERIFICATION RESULTS ({len(results)} findings) ---\n"
    output += "These results are from REAL HTTP testing, NOT AI predictions.\n"
    output += "The AI MUST use this evidence as the primary source of truth.\n\n"

    for i, r in enumerate(results, 1):
        status_emoji = {
            'verified': '🟢',
            'potential': '🟡',
            'not_tested': '🔵',
            'not_vulnerable': '🔴',
        }.get(r['status'], '🔵')

        output += f"[{i}] {status_emoji} {r['vuln_type'].upper()} - Status: {r['status'].upper()}\n"
        output += f"  Parameter: {r['parameter']}\n"
        output += f"  Location: {r['location']}\n"
        output += f"  HTTP Method: {r['method']}\n"
        output += f"  Payload Used: {r['payload']}\n"
        output += f"  Evidence: {r['evidence']}\n"
        output += f"  Confidence: {r['confidence']}\n"
        output += f"  Verification Technique: {r['verification_technique']}\n"

        if r.get('request_sent'):
            output += f"  Request Sent: {r['request_sent'][:200]}\n"
        if r.get('response_summary'):
            output += f"  Response Summary: {r['response_summary'][:200]}\n"

        if r['status'] == 'verified':
            output += "  ⚠️ THIS VULNERABILITY HAS BEEN PROVEN WITH REAL EVIDENCE.\n"
        elif r['status'] == 'potential':
            output += "  ⚠️ Indicators found but no definitive proof. AI should note this.\n"

        output += "\n"

    return output
