import re
from collections import defaultdict

LOG_FILE = "../logs/ssh_auth.log"
REPORT_FILE = "../reports/alerts_report.txt"

FAILED_THRESHOLD = 3  # Number of failed attempts to flag an IP


def analyze_ssh_logs():
    failed_attempts = defaultdict(int)
    successful_logins = []

    try:
        with open(LOG_FILE, "r") as log:
            for line in log:
                # Detect failed SSH login attempts
                failed_match = re.search(
                    r"Failed password.*from (\d+\.\d+\.\d+\.\d+)", line
                )
                if failed_match:
                    ip = failed_match.group(1)
                    failed_attempts[ip] += 1

                # Detect successful SSH logins
                success_match = re.search(
                    r"Accepted password.*from (\d+\.\d+\.\d+\.\d+)", line
                )
                if success_match:
                    successful_logins.append(success_match.group(1))

    except FileNotFoundError:
        print("Log file not found. Please check the log file path.")
        return

    generate_report(failed_attempts, successful_logins)


def generate_report(failed_attempts, successful_logins):
    with open(REPORT_FILE, "w") as report:
        report.write("SSH Log Analysis Report\n")
        report.write("=" * 30 + "\n\n")

        report.write("Potential Brute-Force Attempts:\n")
        for ip, count in failed_attempts.items():
            if count >= FAILED_THRESHOLD:
                report.write(f"- {ip}: {count} failed login attempts\n")

        report.write("\nSuccessful Logins Observed:\n")
        for ip in successful_logins:
            report.write(f"- Successful login from {ip}\n")

    print("Analysis complete. Report saved to reports/alerts_report.txt")


if __name__ == "__main__":
    analyze_ssh_logs()
