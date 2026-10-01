import json
from pathlib import Path
from datetime import datetime


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
LANGUAGES_DIR = BASE_DIR / "languages"


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    # ========================================================
    # LOAD AVAILABLE LANGUAGES
    # ========================================================

    available_languages = {}

    if LANGUAGES_DIR.exists():

        for language_file in sorted(
            LANGUAGES_DIR.glob("*.json")
        ):

            try:
                with open(
                    language_file,
                    "r",
                    encoding="utf-8"
                ) as file:

                    language_data = json.load(file)

                code = language_file.stem

                available_languages[code.upper()] = {
                    "code": code,
                    "name": language_data.get(
                        "language_name",
                        code
                    )
                }

            except (
                OSError,
                json.JSONDecodeError
            ):
                continue


    # ========================================================
    # CHECK LANGUAGES
    # ========================================================

    if not available_languages:

        print("No language files found.")
        print(
            "Não foram encontrados ficheiros de idioma."
        )

        exit()


    # ========================================================
    # LANGUAGE MENU
    # ========================================================

    print()
    print("======================================")
    print("       SECURITY LOG ANALYZER")
    print("======================================")
    print()

    print(
        "Available languages / "
        "Idiomas disponíveis:"
    )

    print()

    for code, data in available_languages.items():

        print(
            f"{code} - {data['name']}"
        )


    # ========================================================
    # SELECT LANGUAGE
    # ========================================================

    language = input(
        "\nLanguage code / Código do idioma: "
    ).strip().upper()


    if language not in available_languages:

        print()
        print(
            "Invalid language / Idioma inválido."
        )

        if "EN" in available_languages:

            language = "EN"

            print(
                "Using English as default."
            )

        else:

            language = next(
                iter(available_languages)
            )


    selected_language = (
        available_languages[language]
    )


    language_file = (
        LANGUAGES_DIR
        / f"{selected_language['code']}.json"
    )


    # ========================================================
    # LOAD LANGUAGE
    # ========================================================

    try:

        with open(
            language_file,
            "r",
            encoding="utf-8"
        ) as file:

            msg = json.load(file)

    except (
        OSError,
        json.JSONDecodeError
    ):

        print(
            "Error loading language file."
        )

        exit()


    # ========================================================
    # LOG FILE
    # ========================================================

    print()

    log_path = input(
        msg.get(
            "log_path",
            "Log file path: "
        )
    ).strip()


    try:

        with open(
            log_path,
            "r",
            encoding="utf-8"
        ) as log_file:

            lines = log_file.readlines()

    except FileNotFoundError:

        print(
            msg.get(
                "file_not_found",
                "File not found."
            )
        )

        exit()

    except OSError:

        print(
            msg.get(
                "file_error",
                "Error opening file."
            )
        )

        exit()


    # ========================================================
    # RESULTS
    # ========================================================

    results = []


    # ========================================================
    # SUPPORTED LOG LEVELS
    # ========================================================

    levels = [
        "EMERGENCY",
        "EMERG",
        "ALERT",
        "CRITICAL",
        "CRIT",
        "ERROR",
        "ERR",
        "WARNING",
        "WARN",
        "NOTICE",
        "INFO",
        "DEBUG"
    ]


    # ========================================================
    # ANALYZE LOG LINES
    # ========================================================

    for line in lines:

        line = line.strip()

        if not line:
            continue


        parts = line.split()


        # ----------------------------------------------------
        # DEFAULT VALUES
        # ----------------------------------------------------

        timestamp = "-"
        time = "-"
        log_format = "UNKNOWN"
        severity = "UNKNOWN"

        risk_code = "low"
        event_code = "information"

        ip_addresses = []
        email_addresses = []

        http_code = "-"
        night_event = False


        # ====================================================
        # SYSLOG
        # ====================================================

        if (
            len(parts) >= 3
            and "-" in parts[0]
            and ":" in parts[1]
        ):

            log_format = "SYSLOG"

            timestamp = (
                parts[0]
                + " "
                + parts[1]
            )

            time = parts[1]

            log_level = (
                parts[2].upper()
            )

            if log_level in levels:

                severity = log_level


        # ====================================================
        # APACHE
        # ====================================================

        elif (
            "[" in line
            and "]" in line
        ):

            log_format = "APACHE"

            start = line.find("[") + 1
            end = line.find("]")

            apache_timestamp = (
                line[start:end]
            )


            try:

                date = datetime.strptime(
                    apache_timestamp,
                    "%d/%b/%Y:%H:%M:%S %z"
                )

                timestamp = (
                    date.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )

                time = (
                    date.strftime(
                        "%H:%M:%S"
                    )
                )

            except ValueError:

                pass


            # ------------------------------------------------
            # HTTP STATUS CODE
            # ------------------------------------------------

            try:

                http_code = int(
                    parts[-2]
                )


                if (
                    200
                    <= http_code
                    < 300
                ):

                    severity = "INFO"


                elif (
                    300
                    <= http_code
                    < 400
                ):

                    severity = "INFO"


                elif (
                    400
                    <= http_code
                    < 500
                ):

                    severity = "WARNING"


                elif (
                    500
                    <= http_code
                    < 600
                ):

                    severity = "ERROR"


            except (
                ValueError,
                IndexError
            ):

                http_code = "-"


        # ====================================================
        # FIND IPv4 ADDRESSES
        # ====================================================

        for part in parts:

            candidate = part.strip(
                "[](),;:\"'<>"
            )


            # Remove possible port:
            # 192.168.1.10:443

            if (
                ":" in candidate
                and "." in candidate
            ):

                left, right = (
                    candidate.rsplit(
                        ":",
                        1
                    )
                )

                if right.isdigit():

                    candidate = left


            blocks = (
                candidate.split(".")
            )


            if len(blocks) == 4:

                valid_ip = True


                for block in blocks:

                    if not block.isdigit():

                        valid_ip = False
                        break


                    number = int(block)


                    if (
                        number < 0
                        or number > 255
                    ):

                        valid_ip = False
                        break


                if (
                    valid_ip
                    and candidate
                    not in ip_addresses
                ):

                    ip_addresses.append(
                        candidate
                    )


        # ====================================================
        # FIND EMAIL ADDRESSES
        # ====================================================

        for part in parts:

            candidate = part.strip(
                "[](),;:\"'<>"
            )


            if "@" in candidate:

                email_parts = (
                    candidate.split("@")
                )


                if len(email_parts) == 2:

                    username = (
                        email_parts[0]
                    )

                    domain = (
                        email_parts[1]
                    )


                    if (
                        username
                        and "." in domain
                        and candidate
                        not in email_addresses
                    ):

                        email_addresses.append(
                            candidate
                        )


        # ====================================================
        # SECURITY EVENT ANALYSIS
        # ====================================================

        text = line.lower()


        # ----------------------------------------------------
        # FAILED AUTHENTICATION
        # ----------------------------------------------------

        if (
            "failed password" in text
            or "failed login" in text
            or "authentication failed" in text
            or "login failed" in text
        ):

            event_code = "failed_auth"
            risk_code = "high"


        # ----------------------------------------------------
        # USER ENUMERATION
        # ----------------------------------------------------

        elif (
            "invalid user" in text
            or "unknown user" in text
            or "user not found" in text
        ):

            event_code = "user_enum"
            risk_code = "high"


        # ----------------------------------------------------
        # POSSIBLE WEBSHELL
        # ----------------------------------------------------

        elif (
            "shell.php" in text
            or "cmd.php" in text
            or "webshell" in text
        ):

            event_code = "webshell"
            risk_code = "high"


        # ----------------------------------------------------
        # SENSITIVE FILES
        # ----------------------------------------------------

        elif (
            "/.env" in text
            or "config.php" in text
            or "/etc/passwd" in text
            or "id_rsa" in text
            or ".ssh" in text
        ):

            event_code = "sensitive_file"
            risk_code = "high"


        # ----------------------------------------------------
        # BACKUPS / DATABASE DUMPS
        # ----------------------------------------------------

        elif (
            "backup.zip" in text
            or "dump.sql" in text
            or "db_backup" in text
            or "site_backup" in text
            or ".sql.gz" in text
            or ".tar.gz" in text
        ):

            event_code = "backup"
            risk_code = "high"


        # ----------------------------------------------------
        # ADMIN INTERFACE RECONNAISSANCE
        # ----------------------------------------------------

        elif (
            "/wp-admin" in text
            or "/phpmyadmin" in text
            or "/admin" in text
            or "/administrator" in text
        ):

            event_code = "admin_scan"
            risk_code = "medium"


        # ----------------------------------------------------
        # BLOCKED NETWORK CONNECTION
        # ----------------------------------------------------

        elif (
            "block tcp" in text
            or "blocked connection" in text
            or "connection denied" in text
            or "connection refused" in text
        ):

            event_code = "blocked"
            risk_code = "medium"


        # ----------------------------------------------------
        # POSSIBLE PHISHING / TYPOSQUATTING
        # ----------------------------------------------------

        elif (
            "paypa1.com" in text
            or "arnazon.com" in text
            or "micosoft.com" in text
            or "gooogle.com" in text
            or "facebok.com" in text
            or "aplle.com" in text
        ):

            event_code = "phishing"
            risk_code = "high"


        # ----------------------------------------------------
        # SUCCESSFUL AUTHENTICATION
        # ----------------------------------------------------

        elif (
            "accepted password" in text
            or "successful login" in text
            or "authentication successful" in text
        ):

            event_code = "login_ok"
            risk_code = "low"


        # ----------------------------------------------------
        # PRIVILEGED COMMAND
        # ----------------------------------------------------

        elif (
            "sudo" in text
            or "runas" in text
        ):

            event_code = "sudo"
            risk_code = "medium"


        # ----------------------------------------------------
        # SESSION DISCONNECTED
        # ----------------------------------------------------

        elif (
            "disconnected" in text
            or "logout" in text
            or "session closed" in text
        ):

            event_code = "disconnect"
            risk_code = "low"


        # ----------------------------------------------------
        # CRITICAL SYSTEM EVENTS
        # ----------------------------------------------------

        elif severity in [
            "EMERGENCY",
            "EMERG",
            "ALERT",
            "CRITICAL",
            "CRIT"
        ]:

            event_code = "severe_system"
            risk_code = "critical"


        # ----------------------------------------------------
        # ERROR
        # ----------------------------------------------------

        elif severity in [
            "ERROR",
            "ERR"
        ]:

            event_code = "system_error"
            risk_code = "medium"


        # ----------------------------------------------------
        # WARNING / NOTICE
        # ----------------------------------------------------

        elif severity in [
            "WARNING",
            "WARN",
            "NOTICE"
        ]:

            event_code = "system_warning"
            risk_code = "medium"


        # ----------------------------------------------------
        # INFO / DEBUG
        # ----------------------------------------------------

        elif severity in [
            "INFO",
            "DEBUG"
        ]:

            event_code = "information"
            risk_code = "low"


        # ====================================================
        # NIGHT-TIME ANALYSIS
        # 00:00 <= hour < 06:00
        # ====================================================

        if time != "-":

            try:

                hour = int(
                    time.split(":")[0]
                )


                if 0 <= hour < 6:

                    night_event = True


                    if risk_code == "medium":

                        risk_code = "high"


            except ValueError:

                pass


        # ====================================================
        # PREPARE IP OUTPUT
        # ====================================================

        if ip_addresses:

            ip_output = ", ".join(
                ip_addresses
            )

        else:

            ip_output = "-"


        # ====================================================
        # PREPARE EMAIL OUTPUT
        # ====================================================

        if email_addresses:

            email_output = ", ".join(
                email_addresses
            )

        else:

            email_output = "-"


        # ====================================================
        # SAVE RESULT
        # ====================================================

        results.append(
            {
                "timestamp": timestamp,
                "time": time,
                "format": log_format,
                "severity": severity,
                "risk": risk_code,
                "event": event_code,
                "ip": ip_output,
                "email": email_output,
                "http_code": http_code,
                "night": night_event,
                "full_line": line
            }
        )


    # ========================================================
    # REPORT
    # ========================================================

    print()
    print(
        msg.get(
            "title",
            "=== SECURITY LOG ANALYSIS ==="
        )
    )

    print()


    # ========================================================
    # TABLE HEADER
    # ========================================================

    print(
        f"| {msg.get('timestamp', 'Timestamp')} "
        f"| {msg.get('severity', 'Severity')} "
        f"| {msg.get('risk', 'Risk')} "
        f"| {msg.get('event', 'Event')} "
        f"| {msg.get('ip', 'IP Address')} "
        f"| {msg.get('email', 'Email')} "
        f"| {msg.get('night', 'Night')} "
        f"| HTTP "
        f"| {msg.get('full_line', 'Full Log Line')} |"
    )


    print(
        "|---|---|---|---|---|---|---|---|---|"
    )


    # ========================================================
    # TABLE CONTENT
    # ========================================================

    for result in results:

        risk_text = msg.get(
            result["risk"],
            result["risk"].upper()
        )


        event_text = msg.get(
            result["event"],
            result["event"]
        )


        if result["night"]:

            night_text = msg.get(
                "yes",
                "YES"
            )

        else:

            night_text = msg.get(
                "no",
                "NO"
            )


        print(
            f"| {result['timestamp']} "
            f"| {result['severity']} "
            f"| {risk_text} "
            f"| {event_text} "
            f"| {result['ip']} "
            f"| {result['email']} "
            f"| {night_text} "
            f"| {result['http_code']} "
            f"| {result['full_line']} |"
        )


    # ========================================================
    # SUMMARY
    # ========================================================

    print()

    total_logs = len(results)

    high_risk = 0
    critical_risk = 0
    night_events = 0


    for result in results:

        if result["risk"] == "high":
            high_risk += 1

        elif result["risk"] == "critical":
            critical_risk += 1

        if result["night"]:
            night_events += 1


    print(
        msg.get(
            "summary",
            "=== SUMMARY ==="
        )
    )

    print()

    print(
        f"{msg.get('total_logs', 'Total logs')}: "
        f"{total_logs}"
    )

    print(
        f"{msg.get('high_risk_events', 'High risk events')}: "
        f"{high_risk}"
    )

    print(
        f"{msg.get('critical_events', 'Critical events')}: "
        f"{critical_risk}"
    )

    print(
        f"{msg.get('night_events', 'Night events')}: "
        f"{night_events}"
    )