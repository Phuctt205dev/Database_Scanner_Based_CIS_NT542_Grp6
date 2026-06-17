import subprocess
import sys
import json
import os
import glob


# ==========================================
# TERMINAL COLORS
# ==========================================

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


# ==========================================
# PATH CONFIG
# ==========================================

ANSIBLE_DIR = "../ansible-lab"

# File scan gốc do scan_all.yml fetch về
REMOTE_RESULT_DIR = f"{ANSIBLE_DIR}/results"

# 6 file json cho remediation đọc
LOCAL_RESULT_DIR = "results"


# ==========================================
# MODULE MAP
# ==========================================

module_map = {

    "2.": "surface_area_result.json",

    "3.": "auth_and_authz_result.json",

    "4.": "password_policies_result.json",

    "5.": "auditing_logging_result.json",

    "6.": "application_development_result.json",

    "7.": "encryption_result.json"
}


# ==========================================
# CREATE RESULT DIRECTORY
# ==========================================

os.makedirs(LOCAL_RESULT_DIR, exist_ok=True)


# ==========================================
# RUN FULL SCAN VIA ANSIBLE
# ==========================================

print(f"\n{CYAN}[1] Running full scan via Ansible...{RESET}\n")

scan_command = [

    "ansible-playbook",

    "-i",

    f"{ANSIBLE_DIR}/inventory.ini",

    f"{ANSIBLE_DIR}/scan_all.yml"
]

scan_process = subprocess.run(scan_command)

if scan_process.returncode != 0:

    print(f"{RED}[ERROR] Scan failed{RESET}")

    sys.exit(1)


# ==========================================
# FIND FETCHED RESULT FILE
# ==========================================

result_files = glob.glob(
    f"{REMOTE_RESULT_DIR}/*_full_scan_result.json"
)

if len(result_files) == 0:

    print(f"{RED}[ERROR] No scan result JSON found{RESET}")

    sys.exit(1)

result_path = result_files[0]

print(
    f"{GREEN}[+] Using result file:{RESET} "
    f"{result_path}"
)


# ==========================================
# LOAD RESULTS
# ==========================================

with open(
    result_path,
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


# ==========================================
# UPDATE LOCAL JSON FILES
# IMPORTANT:
# Remediation playbooks đọc file ở:
# ~/project/nt542-db_scanner-gr06/results
# ==========================================

for filename, data in split_results.items():

    output_path = (
        f"{LOCAL_RESULT_DIR}/{filename}"
    )

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
        f"{GREEN}[+] Updated:{RESET} "
        f"{output_path}"
    )


# ==========================================
# SAVE FULL RESULT LOCALLY
# ==========================================

with open(
    f"{LOCAL_RESULT_DIR}/full_scan_result.json",
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        all_results,
        f,
        indent=4,
        ensure_ascii=False
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

    f"{LOCAL_RESULT_DIR}/full_scan_result.json",

    f"{LOCAL_RESULT_DIR}/full_report.html"
]

report_process = subprocess.run(report_command)

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

    f"{ANSIBLE_DIR}/remediation_surface_area.yml",

    f"{ANSIBLE_DIR}/remediation_auth_safe.yml",

    f"{ANSIBLE_DIR}/remediation_password_policies.yml",

    f"{ANSIBLE_DIR}/remediation_auditing_logging.yml",

    f"{ANSIBLE_DIR}/remediation_application_development.yml",

    f"{ANSIBLE_DIR}/remediation_encryption.yml"
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

        f"{ANSIBLE_DIR}/inventory.ini",

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

rescan_process = subprocess.run(scan_command)

if rescan_process.returncode != 0:

    print(
        f"{RED}[ERROR] Re-scan failed{RESET}"
    )

    sys.exit(1)


# ==========================================
# FIND FINAL RESULT
# ==========================================

result_files = glob.glob(
    f"{REMOTE_RESULT_DIR}/*_full_scan_result.json"
)

if len(result_files) == 0:

    print(
        f"{RED}[ERROR] No final scan result JSON found{RESET}"
    )

    sys.exit(1)

final_result_path = result_files[0]


# ==========================================
# LOAD FINAL RESULTS
# ==========================================

with open(
    final_result_path,
    "r",
    encoding="utf-8"
) as f:

    final_results = json.load(f)


# ==========================================
# PRINT FINAL RESULT
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

    output_path = (
        f"{LOCAL_RESULT_DIR}/{filename}"
    )

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
        f"{GREEN}[+] Updated:{RESET} "
        f"{output_path}"
    )


# ==========================================
# SAVE FINAL RESULT
# ==========================================

with open(
    f"{LOCAL_RESULT_DIR}/final_scan_result.json",
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        final_results,
        f,
        indent=4,
        ensure_ascii=False
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

    f"{LOCAL_RESULT_DIR}/final_scan_result.json",

    f"{LOCAL_RESULT_DIR}/final_report.html"
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