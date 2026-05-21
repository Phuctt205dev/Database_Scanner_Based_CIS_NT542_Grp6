def scan_surface_area(cursor):
    results = []
    
    sys_config_rules = [
        ("2.1", "Ad Hoc Distributed Queries", "0", 0),
        ("2.2", "clr enabled", "0", 0),
        ("2.3", "cross db ownership chaining", "0", 0),
        ("2.4", "Database Mail XPs", "0", 0),
        ("2.5", "Ole Automation Procedures", "0", 0),
        ("2.6", "remote access", "0", 0),
        ("2.8", "scan for startup procs", "0", 0),
        ("2.17", "clr strict security", "1", 1) 
    ]

    for rule_id, config_name, expected_str, expected_int in sys_config_rules:
        cursor.execute(f"SELECT CAST(value_in_use as int) FROM sys.configurations WHERE name = '{config_name}';")
        row = cursor.fetchone()
        if row:
            current_value = int(row[0])
            status = "Compliance" if current_value == expected_int else "Violate"
            results.append({
                "group": "Surface Area Reduction", "rule_id": rule_id,
                "policy": f"Ensure '{config_name}' is set to '{expected_str}'",
                "status": status, "details": f"Giá trị hiện tại: {current_value}"
            })
            
    cursor.execute("SELECT CAST(value_in_use as int) FROM sys.configurations WHERE name = 'remote admin connections' AND SERVERPROPERTY('IsClustered') = 0;")
    row = cursor.fetchone()
    if row:
        current_value = int(row[0])
        status = "Compliance" if current_value == 0 else "Violate"
        results.append({
            "group": "Surface Area Reduction", "rule_id": "2.7",
            "policy": "Ensure 'Remote Admin Connections' is set to '0'",
            "status": status, "details": f"Giá trị hiện tại: {current_value}"
        })

    query_2_11 = """
    IF (select value_data from sys.dm_server_registry where value_name = 'ListenOnAllIPs') = 1
        SELECT count(*) FROM sys.dm_server_registry WHERE registry_key like '%IPAll%' and value_name like '%Tcp%' and value_data='1433'
    ELSE
        SELECT count(*) FROM sys.dm_server_registry WHERE value_name like '%Tcp%' and value_data='1433';
    """
    cursor.execute(query_2_11)
    row = cursor.fetchone()
    if row:
        port_1433_count = int(row[0])
        status = "Compliance" if port_1433_count == 0 else "Violate"
        results.append({
            "group": "Surface Area Reduction", "rule_id": "2.11",
            "policy": "Ensure SQL Server is configured to use non-standard ports",
            "status": status, "details": f"Số lượng port 1433 được tìm thấy: {port_1433_count}"
        })

    query_2_12 = """
    DECLARE @getValue INT;
    EXEC master.sys.xp_instance_regread 
        @rootkey = N'HKEY_LOCAL_MACHINE', 
        @key = N'SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQLServer\\SuperSocketNetLib', 
        @value_name = N'HideInstance', 
        @value = @getValue OUTPUT;
    SELECT ISNULL(@getValue, 0);
    """
    cursor.execute(query_2_12)
    row = cursor.fetchone()
    if row:
        hide_instance_value = int(row[0])
        status = "Compliance" if hide_instance_value == 1 else "Violate"
        results.append({
            "group": "Surface Area Reduction", "rule_id": "2.12",
            "policy": "Ensure 'Hide Instance' option is set to 'Yes'",
            "status": status, "details": "Instance đang bị ẩn (An toàn)" if hide_instance_value == 1 else "Instance đang công khai (Violate)"
        })

    cursor.execute("SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name != 'msdb';")
    violating_dbs = [r[0] for r in cursor.fetchall()]
    status = "Violate" if len(violating_dbs) > 0 else "Compliance"
    results.append({
        "group": "Surface Area Reduction", "rule_id": "2.9",
        "policy": "Ensure 'Trustworthy' Database Property is set to 'Off'",
        "status": status, "details": f"Các DB vi phạm: {violating_dbs}" if violating_dbs else "Tất cả DB đều tắt Trustworthy"
    })

    cursor.execute("SELECT name FROM sys.server_principals WHERE sid = 0x01 AND is_disabled = 0;")
    rows = cursor.fetchall()
    status = "Violate" if len(rows) > 0 else "Compliance"
    results.append({
        "group": "Surface Area Reduction", "rule_id": "2.13",
        "policy": "Ensure the 'sa' Login Account is set to 'Disabled'",
        "status": status, "details": "Tài khoản gốc đang bị bật (Violate)" if rows else "Tài khoản gốc đã được vô hiệu hóa"
    })

    cursor.execute("SELECT name FROM sys.server_principals WHERE sid = 0x01;")
    row = cursor.fetchone()
    if row:
        sa_login_name = str(row[0])
        status = "Violate" if sa_login_name.lower() == 'sa' else "Compliance"
        results.append({
            "group": "Surface Area Reduction", "rule_id": "2.14",
            "policy": "Ensure the 'sa' Login Account has been renamed",
            "status": status, "details": f"Tên tài khoản gốc hiện tại: {sa_login_name}"
        })

    cursor.execute("SELECT name FROM sys.databases WHERE containment <> 0 and is_auto_close_on = 1;")
    violating_auto_close_dbs = [r[0] for r in cursor.fetchall()]
    status = "Violate" if len(violating_auto_close_dbs) > 0 else "Compliance"
    results.append({
        "group": "Surface Area Reduction", "rule_id": "2.15",
        "policy": "Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases",
        "status": status, "details": f"Các Contained DB vi phạm: {violating_auto_close_dbs}" if violating_auto_close_dbs else "An toàn"
    })

    cursor.execute("SELECT name FROM sys.server_principals WHERE name = 'sa';")
    rows = cursor.fetchall()
    status = "Violate" if len(rows) > 0 else "Compliance"
    results.append({
        "group": "Surface Area Reduction", "rule_id": "2.16",
        "policy": "Ensure no login exists with the name 'sa'",
        "status": status, "details": "Phát hiện có tài khoản tên 'sa'" if rows else "Không tồn tại tài khoản tên 'sa'"
    })

    return results