def scan_encryption(cursor):
    results = []

    # =========================================================
    # GET USER DATABASES
    # =========================================================
    cursor.execute("""
        SELECT name
        FROM sys.databases
        WHERE state = 0
          AND database_id > 4;
    """)

    databases = [r[0] for r in cursor.fetchall()]

    # =========================================================
    # RULE 7.1
    # Ensure Symmetric Key is AES_128 or higher
    # =========================================================

    compliant_sym = []
    violating_sym = []

    for db in databases:

        cursor.execute(f"USE [{db}];")

        query_7_1 = """
        SELECT
            name,
            algorithm_desc
        FROM sys.symmetric_keys
        WHERE
            algorithm_desc IN (
                'AES_128',
                'AES_192',
                'AES_256'
            )
            AND name NOT LIKE '##%';
        """

        cursor.execute(query_7_1)

        rows = cursor.fetchall()

        # =====================================================
        # CHƯA CẤU HÌNH KEY NÀO
        # => VIOLATE
        # =====================================================
        if not rows:

            violating_sym.append(
                f"DB '{db}': Chưa cấu hình Symmetric Key"
            )

            continue

        # =====================================================
        # KEY HỢP LỆ
        # =====================================================
        for row in rows:

            key_name = str(row[0])
            algorithm = str(row[1])

            compliant_sym.append(
                f"DB '{db}': {key_name} ({algorithm})"
            )

    status_7_1 = (
        "Compliance"
        if len(violating_sym) == 0
           and len(compliant_sym) > 0
        else "Violate"
    )

    results.append({
        "group": "Encryption",
        "rule_id": "7.1",
        "policy": (
            "Ensure Symmetric Key is AES_128 "
            "or higher"
        ),
        "status": status_7_1,
        "details": (
            f"Symmetric Keys an toàn: {compliant_sym}"
            if status_7_1 == "Compliance"
            else f"Symmetric Key chưa an toàn/chưa cấu hình: {violating_sym}"
        )
    })

    # =========================================================
    # RULE 7.2
    # Ensure Asymmetric Key Size >= 2048
    # =========================================================

    compliant_asym = []
    violating_asym = []

    for db in databases:

        cursor.execute(f"USE [{db}];")

        query_7_2 = """
        SELECT
            name,
            key_length
        FROM sys.asymmetric_keys
        WHERE name NOT LIKE '##%';
        """

        cursor.execute(query_7_2)

        rows = cursor.fetchall()

        # =====================================================
        # CHƯA CẤU HÌNH KEY NÀO
        # => VIOLATE
        # =====================================================
        if not rows:

            violating_asym.append(
                f"DB '{db}': Chưa cấu hình Asymmetric Key"
            )

            continue

        # =====================================================
        # KIỂM TRA KEY LENGTH
        # =====================================================
        for row in rows:

            key_name = str(row[0])
            key_length = int(row[1])

            if key_length >= 2048:

                compliant_asym.append(
                    f"DB '{db}': {key_name} ({key_length} bits)"
                )

            else:

                violating_asym.append(
                    f"DB '{db}': {key_name} ({key_length} bits)"
                )

    status_7_2 = (
        "Compliance"
        if len(violating_asym) == 0
           and len(compliant_asym) > 0
        else "Violate"
    )

    results.append({
        "group": "Encryption",
        "rule_id": "7.2",
        "policy": (
            "Ensure Asymmetric Key Size >= 2048"
        ),
        "status": status_7_2,
        "details": (
            f"Asymmetric Keys an toàn: {compliant_asym}"
            if status_7_2 == "Compliance"
            else f"Asymmetric Key chưa an toàn/chưa cấu hình: {violating_asym}"
        )
    })

    # =========================================================
    # SWITCH BACK TO MASTER
    # =========================================================
    cursor.execute("USE [master];")

    # =========================================================
    # RULE 7.3
    # Ensure Database Backups are Encrypted
    # =========================================================
    query_7_3 = """
    SELECT b.database_name
    FROM msdb.dbo.backupset b
    INNER JOIN sys.databases d
        ON b.database_name = d.name
    WHERE
        b.key_algorithm IS NULL
        AND b.encryptor_type IS NULL
        AND d.is_encrypted = 0;
    """

    cursor.execute(query_7_3)

    unencrypted_backups = sorted(
        set(r[0] for r in cursor.fetchall())
    )

    status = (
        "Violate"
        if len(unencrypted_backups) > 0
        else "Compliance"
    )

    results.append({
        "group": "Encryption",
        "rule_id": "7.3",
        "policy": "Ensure Database Backups are Encrypted",
        "status": status,
        "details": (
            f"Các database có backup chưa mã hóa: "
            f"{unencrypted_backups}"
            if unencrypted_backups
            else "Tất cả backup đều an toàn"
        )
    })

    # =========================================================
    # RULE 7.4
    # Ensure Network Encryption is Configured and Enabled
    # =========================================================
    query_7_4 = """
    SELECT DISTINCT encrypt_option
    FROM sys.dm_exec_connections c
    WHERE
        net_transport <> 'Shared memory'
        AND c.endpoint_id NOT IN (
            SELECT endpoint_id
            FROM sys.database_mirroring_endpoints
            WHERE encryption_algorithm IS NOT NULL
        );
    """

    cursor.execute(query_7_4)

    rows = cursor.fetchall()

    status = (
        "Compliance"
        if any(str(r[0]).upper() == "TRUE" for r in rows)
        else "Violate"
    )

    results.append({
        "group": "Encryption",
        "rule_id": "7.4",
        "policy": (
            "Ensure Network Encryption is "
            "Configured and Enabled"
        ),
        "status": status,
        "details": (
            "Network encryption được bật"
            if status == "Compliance"
            else "Chưa cấu hình Network Encryption"
        )
    })

    return results
