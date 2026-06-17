import subprocess
import sys
import json


# ==========================================
# TERMINAL COLORS
# ==========================================

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


# ==========================================
# CONFIG
# ==========================================

SERVER = "192.168.152.144"
PORT = "51433"
DATABASE = "master"

USERNAME = "scanner_user"
PASSWORD = "StrongPassword123!"


# ==========================================
# MODULE MAP
# ==========================================

module_map = {

    "1.": "surface_area_result.json",

    "2.": "auth_and_authz_result.json",

    "3.": "password_policies_result.json",

    "4.": "auditing_logging_result.json",

    "5.": "application_development_result.json",

    "6.": "encryption_result.json"
}


# ==========================================
# RUN FULL SCAN
# ==========================================

print(f"\n{CYAN}[1] Running full scan...{RESET}\n")

scan_command = [

    "python3",

    "db_scan.py",

    "--server", SERVER,

    "--port", PORT,

    "--database", DATABASE,

    "--username", USERNAME,

    "--password", PASSWORD,

    "--module", "all",

    "--output", "results/full_scan_result.json"
]

scan_process = subprocess.run(
    scan_command,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

if scan_process.returncode != 0:

    print(f"{RED}[ERROR] Scan failed{RESET}")

    sys.exit(1)


# ==========================================
# LOAD RESULTS
# ==========================================

with open(
    "results/full_scan_result.json",
    "r",
    encoding="utf-8"
) as f:

    all_results = json.load(f)


# ==========================================
# PRINT RESULT WITH COLORS
# ==========================================

print(f"\n{CYAN}========== RESULT =========={RESET}\n")

for item in all_results:

    if item["status"] == "Compliance":

        status_text = (
            f"{GREEN}[Compliance]{RESET}"
        )

    else:

        status_text = (
            f"{RED}[Violate]{RESET}"
        )

    print(
        f"{status_text} "
        f"Rule {item['rule_id']}"
    )

    print(f"Policy : {item['policy']}")

    print(f"Details: {item['details']}")

    print("-" * 40)


# ==========================================
# SUMMARY
# ==========================================

total_rules = len(all_results)

compliance_rules = [
    r for r in all_results
    if r["status"] == "Compliance"
]

violate_rules = [
    r for r in all_results
    if r["status"] == "Violate"
]

total_compliance = len(compliance_rules)

total_violate = len(violate_rules)

print(f"\n{CYAN}========== SUMMARY =========={RESET}")

print(f"Total Rules : {total_rules}")

print(
    f"{GREEN}Compliance  : {total_compliance}{RESET}"
)

print(
    f"{RED}Violations  : {total_violate}{RESET}"
)

if total_violate > 0:

    print(f"\n{YELLOW}Violated Rules:{RESET}")

    for item in violate_rules:

        print(
            f"{RED}- Rule {item['rule_id']} : "
            f"{item['policy']}{RESET}"
        )

print(f"{CYAN}============================={RESET}\n")


# ==========================================
# SPLIT MODULE JSON FILES
# ==========================================

print(
    f"{CYAN}[2] Updating module JSON files...{RESET}\n"
)

split_results = {

    "surface_area_result.json": [],

    "auth_and_authz_result.json": [],

    "password_policies_result.json": [],

    "auditing_logging_result.json": [],

    "application_development_result.json": [],

    "encryption_result.json": []
}


for item in all_results:

    rule_id = item["rule_id"]

    for prefix, filename in module_map.items():

        if rule_id.startswith(prefix):

            split_results[filename].append(item)


for filename, data in split_results.items():

    output_path = f"results/{filename}"

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            data,
            f,
            indent=4,
            ensure_ascii=False
        )

    print(
        f"{GREEN}[+] Updated {output_path}{RESET}"
    )


# ==========================================
# GENERATE HTML REPORT
# ==========================================

print(
    f"\n{CYAN}[3] Generating HTML report...{RESET}\n"
)

report_command = [

    "python3",

    "report_generator.py",

    "results/full_scan_result.json",

    "results/full_report.html"
]

report_process = subprocess.run(
    report_command
)

if report_process.returncode != 0:

    print(
        f"{RED}[ERROR] Report generation failed{RESET}"
    )

    sys.exit(1)


# ==========================================
# ASK USER
# ==========================================

choice = input(
    "\nDo you want to remediate all violations? (Y/N): "
)

if choice.upper() != "Y":

    print(
        f"\n{YELLOW}[+] Pipeline terminated.{RESET}"
    )

    sys.exit(0)


# ==========================================
# REMEDIATION PLAYBOOKS
# ==========================================

playbooks = [

    "../ansible-lab/remediation_surface_area.yml",

    "../ansible-lab/remediation_auth_safe.yml",

    "../ansible-lab/remediation_password_policies.yml",

    "../ansible-lab/remediation_auditing_logging.yml",

    "../ansible-lab/remediation_application_development.yml",

    "../ansible-lab/remediation_encryption.yml"
]


# ==========================================
# RUN REMEDIATION
# ==========================================

print(
    f"\n{CYAN}[4] Running remediation playbooks...{RESET}\n"
)

for playbook in playbooks:

    print(
        f"{GREEN}[+] Running {playbook}{RESET}"
    )

    remediation_command = [

        "ansible-playbook",

        "-i",

        "../ansible-lab/inventory.ini",

        playbook
    ]

    remediation_process = subprocess.run(
        remediation_command
    )

    if remediation_process.returncode != 0:

        print(
            f"{RED}[ERROR] Failed: {playbook}{RESET}"
        )


# ==========================================
# RE-SCAN
# ==========================================

print(
    f"\n{CYAN}[5] Running re-scan...{RESET}\n"
)

final_scan_command = [

    "python3",

    "db_scan.py",

    "--server", SERVER,

    "--port", PORT,

    "--database", DATABASE,

    "--username", USERNAME,

    "--password", PASSWORD,

    "--module", "all",

    "--output", "results/final_scan_result.json"
]

final_scan_process = subprocess.run(
    final_scan_command,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

if final_scan_process.returncode != 0:

    print(
        f"{RED}[ERROR] Re-scan failed{RESET}"
    )

    sys.exit(1)


# ==========================================
# LOAD FINAL RESULTS
# ==========================================

with open(
    "results/final_scan_result.json",
    "r",
    encoding="utf-8"
) as f:

    final_results = json.load(f)


# ==========================================
# PRINT FINAL RESULT WITH COLORS
# ==========================================

print(f"\n{CYAN}====== FINAL RESULT ======{RESET}\n")

for item in final_results:

    if item["status"] == "Compliance":

        status_text = (
            f"{GREEN}[Compliance]{RESET}"
        )

    else:

        status_text = (
            f"{RED}[Violate]{RESET}"
        )

    print(
        f"{status_text} "
        f"Rule {item['rule_id']}"
    )

    print(f"Policy : {item['policy']}")

    print(f"Details: {item['details']}")

    print("-" * 40)


# ==========================================
# FINAL SUMMARY
# ==========================================

final_total_rules = len(final_results)

final_compliance_rules = [
    r for r in final_results
    if r["status"] == "Compliance"
]

final_violate_rules = [
    r for r in final_results
    if r["status"] == "Violate"
]

final_total_compliance = len(
    final_compliance_rules
)

final_total_violate = len(
    final_violate_rules
)

print(
    f"\n{CYAN}====== FINAL SUMMARY ======{RESET}"
)

print(f"Total Rules : {final_total_rules}")

print(
    f"{GREEN}Compliance  : "
    f"{final_total_compliance}{RESET}"
)

print(
    f"{RED}Violations  : "
    f"{final_total_violate}{RESET}"
)

if final_total_violate > 0:

    print(f"\n{YELLOW}Violated Rules:{RESET}")

    for item in final_violate_rules:

        print(
            f"{RED}- Rule {item['rule_id']} : "
            f"{item['policy']}{RESET}"
        )

print(
    f"{CYAN}==========================={RESET}\n"
)


# ==========================================
# UPDATE MODULE JSON AGAIN
# ==========================================

print(
    f"{CYAN}[6] Updating module JSON files again...{RESET}\n"
)

split_results = {

    "surface_area_result.json": [],

    "auth_and_authz_result.json": [],

    "password_policies_result.json": [],

    "auditing_logging_result.json": [],

    "application_development_result.json": [],

    "encryption_result.json": []
}


for item in final_results:

    rule_id = item["rule_id"]

    for prefix, filename in module_map.items():

        if rule_id.startswith(prefix):

            split_results[filename].append(item)


for filename, data in split_results.items():

    output_path = f"results/{filename}"

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            data,
            f,
            indent=4,
            ensure_ascii=False
        )

    print(
        f"{GREEN}[+] Updated {output_path}{RESET}"
    )


# ==========================================
# FINAL HTML REPORT
# ==========================================

print(
    f"\n{CYAN}[7] Generating final report...{RESET}\n"
)

final_report_command = [

    "python3",

    "report_generator.py",

    "results/final_scan_result.json",

    "results/final_report.html"
]

final_report_process = subprocess.run(
    final_report_command
)

if final_report_process.returncode != 0:

    print(
        f"{RED}[ERROR] Final report generation failed{RESET}"
    )

    sys.exit(1)


print(
    f"\n{GREEN}[+] Pipeline completed successfully{RESET}"
)