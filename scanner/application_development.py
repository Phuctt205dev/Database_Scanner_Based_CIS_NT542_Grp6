def scan_application_development(cursor):
    results = []

    cursor.execute("SELECT name FROM sys.databases WHERE state = 0;")
    databases = [row[0] for row in cursor.fetchall()]

    violating_assemblies = []

    for db_name in databases:
        query_6_2 = f"""
        USE [{db_name}];
        SELECT name, permission_set_desc
        FROM sys.assemblies
        WHERE is_user_defined = 1 AND name <> 'Microsoft.SqlServer.Types';
        """
        try:
            cursor.execute(f"USE [{db_name}];")
            cursor.execute(
                "SELECT name, permission_set_desc "
                "FROM sys.assemblies "
                "WHERE is_user_defined = 1 AND name <> 'Microsoft.SqlServer.Types';"
            )
            for assembly_name, permission_set in cursor.fetchall():
                if str(permission_set).upper() != 'SAFE_ACCESS':
                    violating_assemblies.append(
                        f"DB '{db_name}': Assembly '{assembly_name}' đang có quyền '{permission_set}'"
                    )
        except Exception:
            pass

    cursor.execute("USE [master];")

    status = "Violate" if violating_assemblies else "Compliance"
    results.append({
        "group": "Application Development",
        "rule_id": "6.2",
        "policy": "Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies",
        "status": status,
        "details": (
            f"Các assemblies vi phạm: {violating_assemblies}"
            if violating_assemblies
            else "Tất cả user-defined CLR Assemblies đều tuân thủ (SAFE_ACCESS)"
        ),
    })

    return results