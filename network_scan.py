#!/usr/bin/env python3
import sys
import subprocess
import logging
import socket
import ipaddress
import threading
import os
import platform
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict
import psutil
import argparse
from tabulate import tabulate

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

try:
    from mac_vendor_lookup import MacLookup
except ImportError:
    MacLookup = None

try:
    import msvcrt

    def getch():
        ch = msvcrt.getch()
        try:
            return ch.decode('utf-8')
        except Exception:
            return ch
except ImportError:
    import tty
    import termios

    def getch():
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

REQUIRED_LIBRARIES = {
    "psutil": "psutil",
    "tqdm": "tqdm",
    "mac-vendor-lookup": "mac_vendor_lookup",
    "tabulate": "tabulate",
}

MAX_WORKERS = 500   # Increased number of threads for faster scanning
SCAN_TIMEOUT = 1

def install_libraries():
    libraries_to_install = []
    for pip_name, module_name in REQUIRED_LIBRARIES.items():
        try:
            __import__(module_name)
        except ImportError:
            libraries_to_install.append(pip_name)
    if libraries_to_install:
        logger.info(f"Missing libraries detected: {', '.join(libraries_to_install)}. Installing...")
        for lib in libraries_to_install:
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", lib],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                logger.info(f"{lib} successfully installed!")
            except subprocess.CalledProcessError as e:
                logger.error(f"Unable to install {lib}. Error: {e}")
                sys.exit(1)
    else:
        logger.info("All required libraries are already installed.")

def check_and_install():
    logger.info("Checking and installing required libraries...")
    install_libraries()
    logger.info("Installation completed. Relaunch the script without the --install flag.")

def system_ping(ip: str) -> bool:
    system_name = platform.system().lower()
    if system_name == 'windows':
        # -n 1: send 1 echo request, -w 500: wait 500ms for reply
        command = ['ping', '-n', '1', '-w', '500', ip]
    else:
        # -c 1: send 1 echo request, -W 1: wait 1 second for reply
        command = ['ping', '-c', '1', '-W', '1', ip]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception as e:
        logger.debug(f"Error pinging {ip}: {e}")
        return False

def parse_arp_table() -> Dict[str, str]:
    arp_dict = {}
    try:
        output = subprocess.check_output("arp -a", shell=True).decode()
        for line in output.splitlines():
            if platform.system().lower() == "windows":
                parts = line.split()
                if len(parts) >= 3:
                    ip_candidate = parts[0]
                    mac_candidate = parts[1]
                    try:
                        ipaddress.ip_address(ip_candidate)
                        arp_dict[ip_candidate] = mac_candidate
                    except ValueError:
                        continue
            else:
                match = re.search(r'\(([\d\.]+)\) at ([0-9a-f:]+)', line, re.IGNORECASE)
                if match:
                    ip_candidate = match.group(1)
                    mac_candidate = match.group(2)
                    arp_dict[ip_candidate] = mac_candidate
    except Exception as e:
        logger.error(f"Error reading ARP table: {e}")
    return arp_dict

def get_mac_info_from_arp(ip: str, arp_table: Dict[str, str], mac_lookup=None) -> Dict[str, str]:
    mac = arp_table.get(ip, "N/A")
    vendor = "Unknown"
    if mac != "N/A" and mac_lookup:
        try:
            vendor = mac_lookup.lookup(mac)
        except Exception:
            vendor = "Unknown"
    return {"MAC": mac, "Vendor": vendor}

class NetworkScanner:
    def __init__(self):
        self.terminate_scan = threading.Event()
        if MacLookup:
            try:
                self.mac_lookup = MacLookup()
                self.mac_lookup.update_vendors()
            except Exception:
                logger.warning("Unable to update MAC database, using local version")
                self.mac_lookup = None
        else:
            self.mac_lookup = None
        if platform.system().lower() == 'linux':
            try:
                if os.geteuid() != 0:
                    logger.info("Running without administrator privileges (some details may be limited).")
            except AttributeError:
                pass

    def list_interfaces(self) -> List[Dict]:
        interfaces = []
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            ip_entries = [addr for addr in addr_list if addr.family == socket.AF_INET]
            if not ip_entries:
                continue
            interface_info = {
                "interface": iface,
                "status": "UP" if stats.get(iface) and stats[iface].isup else "DOWN",
                "ips": [{"address": ip_entry.address, "netmask": ip_entry.netmask} for ip_entry in ip_entries]
            }
            interfaces.append(interface_info)
        return interfaces

    def calculate_network(self, ip: str, netmask: str) -> ipaddress.IPv4Network:
        try:
            return ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
        except ValueError as e:
            logger.error(f"Error configuring network: {e}")
            sys.exit(1)

    def ping_host(self, ip: str) -> (bool, float):
        """Ping host and measure response time in ms."""
        start_time = time.perf_counter()
        alive = system_ping(ip)
        end_time = time.perf_counter()
        response_time = round((end_time - start_time) * 1000, 2) if alive else None
        return alive, response_time

    def scan_network(self, network: ipaddress.IPv4Network) -> List[Dict]:
        self.terminate_scan.clear()
        hosts = []
        try:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(self.ping_host, str(ip)): ip for ip in network.hosts()}
                if tqdm:
                    pbar = tqdm(total=len(futures), desc="Scanning network", unit="IP")
                else:
                    pbar = None
                for future in as_completed(futures):
                    if self.terminate_scan.is_set():
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    ip_str = str(futures[future])
                    try:
                        alive, response_time = future.result()
                        if alive:
                            host_info = {"IP": ip_str, "Response Time": response_time}
                            host_info["Hostname"] = self.resolve_hostname(ip_str)
                            hosts.append(host_info)
                    except Exception as e:
                        logger.debug(f"Error scanning {ip_str}: {e}")
                    finally:
                        if pbar:
                            pbar.update(1)
                if pbar:
                    pbar.close()
        except KeyboardInterrupt:
            self.terminate_scan.set()
            logger.info("\nScan interrupted by user.")
        return hosts

    @staticmethod
    def resolve_hostname(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.timeout):
            return "N/A"

def main():
    if sys.version_info < (3, 7):
        logger.error("Python 3.7 or higher is required.")
        sys.exit(1)
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        logger.error("pip is not installed or configured correctly.")
        sys.exit(1)
    parser = argparse.ArgumentParser(description="Advanced Network Scanner")
    parser.add_argument('--install', action='store_true', help="Install missing libraries then exit.")
    parser.add_argument('-i', '--interface', help="Name of the network interface to use (e.g., eth0, Wi-Fi, etc.)")
    args = parser.parse_args()
    if args.install:
        check_and_install()
        sys.exit(0)
    scanner = NetworkScanner()
    interfaces = scanner.list_interfaces()
    if not interfaces:
        logger.error("No active network interfaces available.")
        sys.exit(1)
    if args.interface:
        selected = next((i for i in interfaces if i['interface'] == args.interface), None)
        if not selected:
            logger.error(f"Interface '{args.interface}' not found among available interfaces.")
            sys.exit(1)
    else:
        logger.info("\nAvailable interfaces:\n")
        table = [[idx, i['interface'], i['status'], "\n".join(f"{ip_['address']}/{ip_['netmask']}" for ip_ in i['ips'])]
                 for idx, i in enumerate(interfaces)]
        logger.info(tabulate(table, headers=["Index", "Interface", "Status", "IP/Mask"], tablefmt="grid"))
        if len(interfaces) < 10:
            logger.info("\nSelect the interface index to use (press the corresponding key): ")
            ch = getch()
            try:
                index = int(ch)
            except ValueError:
                logger.error("Invalid key. Exiting.")
                sys.exit(1)
            if index < 0 or index >= len(interfaces):
                logger.error("Invalid index. Exiting.")
                sys.exit(1)
            selected = interfaces[index]
        else:
            name = input("\nEnter the name of the interface to use: ")
            selected = next((i for i in interfaces if i['interface'] == name), None)
            if not selected:
                logger.error(f"Interface '{name}' not found among available interfaces.")
                sys.exit(1)
    ip_info = selected['ips'][0]
    network = scanner.calculate_network(ip_info['address'], ip_info['netmask'])
    logger.info(f"\nStarting scan on network {network} using interface '{selected['interface']}'...")
    logger.info("Press Ctrl+C to stop the scan.\n")
    results = scanner.scan_network(network)
    
    arp_table = parse_arp_table()
    for host in results:
        mac_info = get_mac_info_from_arp(host["IP"], arp_table, scanner.mac_lookup)
        host.update(mac_info)
    
    results.sort(key=lambda host: ipaddress.IPv4Address(host["IP"]))
    
    # Combine IP and MAC in one cell with newline separation
    data = []
    for host in results:
        ip_mac = f"{host['IP']}\n{host.get('MAC', 'N/A')}"
        hostname = host.get("Hostname", "N/A")
        response_time = host.get("Response Time", "N/A")
        vendor = host.get("Vendor", "Unknown")
        data.append([ip_mac, hostname, response_time, vendor])
    
    headers = ["IP / MAC", "Hostname", "Response Time (ms)", "Vendor"]
    logger.info("\n" + tabulate(data, headers=headers, tablefmt="grid"))
    logger.info(f"\nFound {len(results)} active devices.")

if __name__ == "__main__":
    main()
