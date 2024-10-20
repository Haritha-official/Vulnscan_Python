import nmap
import re

def validate_ipv4(ip):
    # Regular expression for validating IPv4 address
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

def validate_ipv6(ip):
    # Regular expression for validating IPv6 address
    pattern = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
    return pattern.match(ip) is not None

def get_ip_address():
    while True:
        ip_type = input("Enter IP version (4 or 6): ")
        if ip_type == '4':
            ip = input("Enter the IPv4 address: ")
            if validate_ipv4(ip):
                return ip, 'ipv4'
            else:
                print("Invalid IPv4 address format. Please try again.")
        elif ip_type == '6':
            ip = input("Enter the IPv6 address: ")
            if validate_ipv6(ip):
                return ip, 'ipv6'
            else:
                print("Invalid IPv6 address format. Please try again.")
        else:
            print("Invalid input. Please enter '4' for IPv4 or '6' for IPv6.")

def get_port_range():
    while True:
        try:
            port_range = input("Enter the port range (e.g., 20-80): ")
            start_port, end_port = map(int, port_range.split('-'))
            if 0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port:
                return port_range
            else:
                print("Port numbers must be between 0 and 65535. Try again.")
        except ValueError:
            print("Invalid port range format. Please try again.")

def scan_ports(ip, ip_type, port_range):
    scanner = nmap.PortScanner()
    print(f"Scanning {ip} on ports {port_range}...")

    try:
        if ip_type == 'ipv4':
            # Service version detection with OS detection and verbosity
            scanner.scan(ip, port_range, arguments='-sV -O --script vuln -v')
        else:
            scanner.scan(ip, port_range, arguments='-sV -O --script vuln -6 -v')

        if ip not in scanner.all_hosts():
            print(f"No results found for {ip}. The host might be down or unreachable.")
            return

        for proto in scanner[ip].all_protocols():
            ports = scanner[ip][proto].keys()
            for port in sorted(ports):
                state = scanner[ip][proto][port]['state']
                service = scanner[ip][proto][port].get('name', 'Unknown')
                version = scanner[ip][proto][port].get('version', 'Unknown') or 'Unknown'

                print(f"Port {port}: {state} | Service: {service} | Version: {version}")

                # Check for vulnerability scan results
                if 'script' in scanner[ip][proto][port]:
                    vuln_results = scanner[ip][proto][port]['script']
                    if vuln_results:
                        print("  Vulnerabilities found:")
                        for vuln_name, vuln_detail in vuln_results.items():
                            print(f"    - {vuln_name}: {vuln_detail}")
                    else:
                        print("  No vulnerabilities found.")

    except Exception as e:
        print(f"Error scanning {ip}: {str(e)}")

if __name__ == "__main__":
    ip, ip_type = get_ip_address()
    port_range = get_port_range()
    scan_ports(ip, ip_type, port_range)
