import re

def analyze_log(file_name):
    # Severity counters
    severity_count = {
        "ERROR": 0,
        "WARNING": 0,
        "WARN": 0,
        "INFO": 0,
        "CRITICAL": 0
    }

    # Risk analysis
    risk_score = 0
    ip_count = {}
    suspicious_lines = []

    suspicious_keywords = [
        "failed",
        "unauthorized",
        "access denied",
        "forbidden",
        "authentication failed",
        "brute force",
        "invalid",
        "timeout"
    ]

    try:
        with open(file_name, "r") as file:
            for line in file:
                line_lower = line.lower()

                # Detect severity (format-agnostic)
                for sev in severity_count:
                    if sev in line:
                        severity_count[sev] += 1
                        if sev in ["ERROR", "CRITICAL"]:
                            risk_score += 1

                # Detect suspicious keywords
                for word in suspicious_keywords:
                    if word in line_lower:
                        risk_score += 2
                        suspicious_lines.append(line.strip())
                        break

                # Extract IP addresses
                ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)
                for ip in ips:
                    ip_count[ip] = ip_count.get(ip, 0) + 1

    except FileNotFoundError:
        print("Log file not found.")
        return

    # IP-based risk
    for ip, count in ip_count.items():
        if count >= 5:
            risk_score += 3

    # ---------------- OUTPUT ----------------

    print("\nSEVERITY SUMMARY")
    print("----------------")
    for sev, count in severity_count.items():
        print(f"{sev}: {count}")

    print("\nTOP IP ADDRESSES")
    print("----------------")
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip} -> {count}")

    print("\nSUSPICIOUS EVENTS (sample)")
    print("--------------------------")
    for line in suspicious_lines[:5]:
        print(line)

    print("\nSYSTEM SECURITY STATUS")
    print("----------------------")
    if risk_score >= 10:
        print("POSSIBLE SYSTEM COMPROMISE DETECTED")
    else:
        print("NO IMMEDIATE SIGNS OF COMPROMISE")

    print("\nFinal Risk Score:", risk_score)


# Run analyzer
analyze_log("sample.log")
