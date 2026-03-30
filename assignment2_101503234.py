"""
Author: Sanyoung Yoon
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print("Python Version:", platform.python_version())
print("Operating System:", os.name)

# Stores common port numbers and their associated services
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target


# Q3: What is the benefit of using @property and @target.setter?
# Using @property and @target.setter gives controlled access to a private variable.
# It allows validation before the value is changed.
# This makes the code safer and supports encapsulation.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value != "":
            self.__target = value
        else:
            print("Error: Target cannot be empty")

    def __del__(self):
        print("NetworkTool instance destroyed")

# Q1: How does PortScanner reuse code from NetworkTool?
# TODO: Your 2-4 sentence answer here... (Part 2, Q1)
# PortScanner reuses code from NetworkTool through inheritance.
# It gets the target property and validation logic from the parent class.
# This avoids repeating code and makes the program easier to maintain.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        sock = None

#     Q4: What would happen without try-except here?
# Without try-except, a socket error could stop the whole program.
# The scan might crash before checking the remaining ports.
# Exception handling keeps the scanner running even if one port causes an error.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            if sock:
                sock.close()

    def get_open_ports(self):
#     Q2: Why do we use threading instead of scanning one port at a time?
# Threading lets the program scan multiple ports at the same time.
# This makes the scan much faster than checking ports one by one.
# It is especially useful when scanning a large range of ports.
        return [result for result in self.scan_results if result[1] == "Open"]
    
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port,end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )
        """)

        for result in results:
            cursor.execute("""
            INSERT INTO scans (target, port, status, service, scan_date)
            VALUES (?, ?, ?, ?, ?)
            """, (target, result[0], result[1], result[2], str(datetime.datetime.now())))

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print(f"Database error: {e}")

def load_past_scans():
    conn = None
    try:
        if not os.path.exists("scan_history.db"):
            print("No past scans found.")
            return
            
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        if len(rows) == 0:
            print("No past scans found.")
        else:
            for row in rows:
                print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")

    except sqlite3.Error:
        print("No past scans found.")

    finally:
        if conn:
            conn.close()
# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    target = input("Enter target IP: ").strip()
    if target == "":
        target = "127.0.0.1"

    try:
        start_port = int(input("Enter starting port number: "))
        end_port = int(input("Enter ending port number: "))

        if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024")
        elif end_port < start_port:
            print("Ending port must be greater than or equal to starting port")
        else:
            scanner = PortScanner(target)
            print(f"Scanning {target} from port {start_port} to {end_port}...")

            scanner.scan_range(start_port,end_port)

            open_ports = scanner.get_open_ports()

            print(f"--- Scan Results for {target} ---")
            for port, status, service_name in open_ports:
                print(f"Port {port}: {status} ({service_name})")
                print("------")

            print(f"Total open ports found: {len(open_ports)}")

            save_results(target, scanner.scan_results)

            choice = input("Would you like to see past scan history? (yes/no): ").strip().lower()
            if choice == "yes":
                load_past_scans()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")
# Q5: New Feature Proposal
# One extra feature I would add is a filter for risky open ports.
# For example, it could show only remote access or database ports.
# This would help users focus on ports that may have higher security risk.