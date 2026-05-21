# scanner/auditing_logging.py
def scan_auditing_logging(cursor):
    results = []

    # =====================================================
    # Rule 5.1:
    # Ensure 'Maximum number of error log files' is >= 12
    # =====================================================
    query_5_1 = """
    DECLARE @NumErrorLogs INT;

    EXEC xp_instance_regread
        N'HKEY_LOCAL_MACHINE',
        N'Software\\Microsoft\\MSSQLServer\\MSSQLServer',
        N'NumErrorLogs',
        @NumErrorLogs OUTPUT;

    SELECT @NumErrorLogs;
    """

    try:

        cursor.execute(query_5_1)
        row = cursor.fetchone()

        if row and row[0] is not None:

            num_error_logs = int(row[0])

            status = (
                "Compliance"
                if num_error_logs >= 12
                else "Violate"
            )

            details = (
                f"Số lượng Error Logs giữ lại: {num_error_logs}"
            )

        else:

            status = "Violate"

            details = (
                "Không đọc được cấu hình NumErrorLogs"
            )

    except Exception as e:

        status = "Violate"

        details = (
            f"Lỗi khi đọc registry NumErrorLogs: {str(e)}"
        )

    results.append({
        "group": "Auditing and Logging",
        "rule_id": "5.1",
        "policy": "Ensure 'Maximum number of error log files' is >= 12",
        "status": status,
        "details": details
    })

    # =====================================================
    # Rule 5.2:
    # Ensure 'Default Trace Enabled' = 1
    # =====================================================
    cursor.execute("""
        SELECT CAST(value_in_use as int)
        FROM sys.configurations
        WHERE name = 'default trace enabled';
    """)

    row = cursor.fetchone()

    if row:

        default_trace_enabled = int(row[0])

        status = (
            "Compliance"
            if default_trace_enabled == 1
            else "Violate"
        )

        results.append({
            "group": "Auditing and Logging",
            "rule_id": "5.2",
            "policy": "Ensure 'Default Trace Enabled' is set to '1'",
            "status": status,
            "details": (
                f"Giá trị Default Trace hiện tại: "
                f"{default_trace_enabled}"
            )
        })

    # =====================================================
    # Rule 5.3:
    # Ensure 'Login Auditing' = failed logins
    # =====================================================
    cursor.execute("EXEC xp_loginconfig 'audit level';")

    row = cursor.fetchone()

    if row:

        audit_level = str(row[1])

        status = (
            "Compliance"
            if audit_level.lower() in ['failure', 'all']
            else "Violate"
        )

        results.append({
            "group": "Auditing and Logging",
            "rule_id": "5.3",
            "policy": "Ensure 'Login Auditing' is set to 'failed logins'",
            "status": status,
            "details": (
                f"Cấu hình Audit level hiện hành: "
                f"{audit_level}"
            )
        })

    # =====================================================
    # Rule 5.4:
    # Ensure SQL Server Audit is configured properly
    # =====================================================
    query_5_4 = """
    SELECT
        SAD.audit_action_name,
        CASE S.is_state_enabled
            WHEN 1 THEN 'Y'
            ELSE 'N'
        END AS audit_enabled,
        CASE SA.is_state_enabled
            WHEN 1 THEN 'Y'
            ELSE 'N'
        END AS spec_enabled,
        SAD.audited_result
    FROM sys.server_audit_specification_details AS SAD
    JOIN sys.server_audit_specifications AS SA
        ON SAD.server_specification_id = SA.server_specification_id
    JOIN sys.server_audits AS S
        ON SA.audit_guid = S.audit_guid
    WHERE SAD.audit_action_id IN (
        'CNAU',
        'LGFL',
        'LGSD',
        'ADDP',
        'ADSP',
        'OPSV'
    )
       OR (
            SAD.audit_action_id IN ('DAGS', 'DAGF')
            AND (
                SELECT COUNT(*)
                FROM sys.databases
                WHERE containment = 1
            ) > 0
       );
    """

    cursor.execute(query_5_4)

    rows = cursor.fetchall()

    required_actions = [
        'AUDIT_CHANGE_GROUP',
        'FAILED_LOGIN_GROUP',
        'SUCCESSFUL_LOGIN_GROUP',
        'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
        'SERVER_ROLE_MEMBER_CHANGE_GROUP',
        'SERVER_OPERATION_GROUP'
    ]

    contained_db_actions = [
        'SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP',
        'FAILED_DATABASE_AUTHENTICATION_GROUP'
    ]

    found_actions = set()

    violation_details = []

    # =====================================================
    # Check contained databases
    # =====================================================
    cursor.execute("""
        SELECT COUNT(*)
        FROM sys.databases
        WHERE containment = 1;
    """)

    contained_db_count = cursor.fetchone()[0]

    for row in rows:

        audit_action_name = str(row[0])

        audit_enabled = str(row[1])

        spec_enabled = str(row[2])

        audited_result = str(row[3])

        found_actions.add(audit_action_name)

        if audit_enabled != 'Y':

            violation_details.append(
                f"{audit_action_name}: Audit chưa enabled"
            )

        if spec_enabled != 'Y':

            violation_details.append(
                f"{audit_action_name}: "
                f"Audit Specification chưa enabled"
            )

        if audited_result.lower() not in [
            'success and failure',
            'all'
        ]:

            violation_details.append(
                f"{audit_action_name}: "
                f"audited_result chưa gồm cả success và failure"
            )

    # =====================================================
    # Check required actions
    # =====================================================
    for action in required_actions:

        if action not in found_actions:

            violation_details.append(
                f"Thiếu audit action: {action}"
            )

    # =====================================================
    # Check contained DB actions if needed
    # =====================================================
    if contained_db_count > 0:

        for action in contained_db_actions:

            if action not in found_actions:

                violation_details.append(
                    f"Thiếu contained DB audit action: {action}"
                )

    status = (
        "Compliance"
        if len(violation_details) == 0
        else "Violate"
    )

    results.append({
        "group": "Auditing and Logging",
        "rule_id": "5.4",
        "policy": "Ensure SQL Server Audit is configured properly",
        "status": status,
        "details": (
            "Tất cả audit requirements đều tuân thủ"
            if status == "Compliance"
            else "; ".join(violation_details)
        )
    })

    return results
