import json
import argparse
import pyodbc
import os

from scanner.surface_area import scan_surface_area
from scanner.auth_and_authz import scan_auth_and_authz
from scanner.password_policies import scan_password_policies
from scanner.auditing_logging import scan_auditing_logging
from scanner.application_development import scan_application_development
from scanner.encryption import scan_encryption


def connect_sql_server(server, port, database, username, password):

    conn_str = (
        "DRIVER={ODBC Driver 18 for SQL Server};"
        f"SERVER={server},{port};"
        f"DATABASE={database};"
        f"UID={username};"
        f"PWD={password};"
        "Encrypt=yes;"
        "TrustServerCertificate=yes;"
    )

    return pyodbc.connect(conn_str)


def print_banner():

    print("=" * 50)
    print(" CIS Microsoft SQL Server 2022 Scanner ")
    print("=" * 50)


def print_summary(results):

    total = len(results)

    compliant = len([
        r for r in results
        if r["status"] == "Compliance"
    ])

    violate = len([
        r for r in results
        if r["status"] == "Violate"
    ])

    print("\n========== SUMMARY ==========")
    print(f"Total Rules : {total}")
    print(f"Compliance  : {compliant}")
    print(f"Violations  : {violate}")
    print("=============================\n")


def export_json(results, output_path):

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(f"[+] Exported result -> {output_path}")


def get_output_path(module_name):

    os.makedirs("results", exist_ok=True)

    output_map = {
        "surface_area": "results/surface_area_result.json",
        "auth_and_authz": "results/auth_and_authz_result.json",
        "password_policies": "results/password_policies_result.json",
        "auditing_logging": "results/auditing_logging_result.json",
        "application_development": "results/application_development_result.json",
        "encryption": "results/encryption_result.json",
        "all": "results/full_scan_result.json"
    }

    return output_map.get(
        module_name,
        "results/scan_result.json"
    )


def main():

    parser = argparse.ArgumentParser(
        description="CIS SQL Server 2022 Scanner"
    )

    parser.add_argument(
        "--server",
        required=True,
        help="SQL Server IP or hostname"
    )

    parser.add_argument(
        "--port",
        default="1433",
        help="SQL Server port"
    )

    parser.add_argument(
        "--database",
        default="master",
        help="Database name"
    )

    parser.add_argument(
        "--username",
        required=True,
        help="SQL login username"
    )

    parser.add_argument(
        "--password",
        required=True,
        help="SQL login password"
    )

    parser.add_argument(
        "--output",
        default=None,
        help="Custom output JSON file"
    )

    parser.add_argument(
        "--module",
        choices=[
            "surface_area",
            "auth_and_authz",
            "password_policies",
            "auditing_logging",
            "application_development",
            "encryption",
            "all"
        ],
        default="all",
        help="Select scan module"
    )

    args = parser.parse_args()

    print_banner()

    try:

        print("[*] Connecting SQL Server...")

        conn = connect_sql_server(
            args.server,
            args.port,
            args.database,
            args.username,
            args.password
        )

        cursor = conn.cursor()

        print("[+] Connected successfully")

        all_results = []

        # ==========================================
        # SURFACE AREA
        # ==========================================
        if args.module in ["surface_area", "all"]:

            print("[*] Running Surface Area Reduction scan...")

            surface_results = scan_surface_area(cursor)

            all_results.extend(surface_results)

        # ==========================================
        # AUTH & AUTHZ
        # ==========================================
        if args.module in ["auth_and_authz", "all"]:

            print("[*] Running Authentication & Authorization scan...")

            auth_results = scan_auth_and_authz(cursor)

            all_results.extend(auth_results)

        # ==========================================
        # PASSWORD POLICIES
        # ==========================================
        if args.module in ["password_policies", "all"]:

            print("[*] Running Password Policies scan...")

            password_results = scan_password_policies(cursor)

            all_results.extend(password_results)

        # ==========================================
        # AUDITING & LOGGING
        # ==========================================
        if args.module in ["auditing_logging", "all"]:

            print("[*] Running Auditing & Logging scan...")

            auditing_results = scan_auditing_logging(cursor)

            all_results.extend(auditing_results)

        # ==========================================
        # APPLICATION DEVELOPMENT
        # ==========================================
        if args.module in ["application_development", "all"]:

            print("[*] Running Application Development scan...")

            application_results = scan_application_development(cursor)

            all_results.extend(application_results)

        # ==========================================
        # ENCRYPTION
        # ==========================================
        if args.module in ["encryption", "all"]:

            print("[*] Running Encryption scan...")

            encryption_results = scan_encryption(cursor)

            all_results.extend(encryption_results)

        print("\n========== RESULT ==========\n")

        for item in all_results:

            print(f"[{item['status']}] Rule {item['rule_id']}")
            print(f"Policy : {item['policy']}")
            print(f"Details: {item['details']}")
            print("-" * 40)

        print_summary(all_results)

        output_path = (
            args.output
            if args.output
            else get_output_path(args.module)
        )

        export_json(
            all_results,
            output_path
        )

        conn.close()

        print("[+] Scan completed")

    except pyodbc.Error as e:

        print("\n[DATABASE ERROR]")
        print(str(e))

    except Exception as e:

        print("\n[ERROR]")
        print(str(e))


if __name__ == "__main__":
    main()
