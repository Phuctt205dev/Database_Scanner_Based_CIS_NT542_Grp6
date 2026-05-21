# scanner/password_policies.py
def scan_password_policies(cursor):
    results = []

    # =========================
    # Rule 4.1: MUST_CHANGE = ON
    # =========================
    query_4_1 = """
    SELECT name
    FROM sys.sql_logins
    WHERE LOGINPROPERTY(name, 'IsMustChange') <> 1
       OR LOGINPROPERTY(name, 'IsMustChange') IS NULL;
    """
    cursor.execute(query_4_1)
    rows = cursor.fetchall()

    status = "Violate" if len(rows) > 0 else "Compliance"
    violators_4_1 = [r for r in rows]

    results.append({
        "group": "Password Policies",
        "rule_id": "4.1",
        "policy": "Ensure 'MUST_CHANGE' Option is set to 'ON' for all SQL authenticated logins",
        "status": status,
        "details": f"Các tài khoản vi phạm MUST_CHANGE: {violators_4_1}" if violators_4_1 else "Tất cả tài khoản đều tuân thủ"
    })

    # =========================
    # Rule 4.2: Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All Sysadmin Logins
    # =========================
    query_4_2 = """
    SELECT l.[name] FROM sys.sql_logins AS l
    WHERE IS_SRVROLEMEMBER('sysadmin',name) = 1 AND l.is_expiration_checked <> 1
    UNION ALL
    SELECT l.[name] FROM sys.sql_logins AS l
    JOIN sys.server_permissions AS p ON l.principal_id = p.grantee_principal_id
    WHERE p.type = 'CL' AND p.state IN ('G', 'W') AND l.is_expiration_checked <> 1;
    """
    cursor.execute(query_4_2)
    rows = cursor.fetchall()

    status = "Violate" if len(rows) > 0 else "Compliance"
    violators_4_2 = [r for r in rows]

    results.append({
        "group": "Password Policies",
        "rule_id": "4.2",
        "policy": "Ensure 'CHECK_EXPIRATION' is 'ON' for Sysadmin/CONTROL SERVER",
        "status": status,
        "details": f"Các tài khoản vi phạm: {violators_4_2}" if violators_4_2 else "Tất cả tài khoản đều tuân thủ"
    })

    # =========================
    # Rule 4.3: CHECK_POLICY = ON
    # =========================
    cursor.execute("SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0;")
    rows = cursor.fetchall()

    status = "Violate" if len(rows) > 0 else "Compliance"
    violators = [row for row in rows]

    results.append({
        "group": "Password Policies",
        "rule_id": "4.3",
        "policy": "Ensure 'CHECK_POLICY' Option is set to 'ON'",
        "status": status,
        "details": f"Các tài khoản vi phạm CHECK_POLICY: {violators}" if violators else "Tất cả tài khoản đều tuân thủ"
    })

    return results
