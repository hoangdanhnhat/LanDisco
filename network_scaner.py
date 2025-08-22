#!/usr/bin/env python3
"""
Network Device Discovery Script
Scans the local network to discover connected devices and displays their information
in a beautiful table format.
"""

import subprocess
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import netifaces
import psutil
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
import argparse
import ipaddress
import platform
import re


class NetworkScanner:
    def __init__(self):
        self.console = Console()
        self.devices = []
        self.lock = threading.Lock()
    
    def get_local_networks(self):
        """Get all local network ranges"""
        networks = []
        for interface in netifaces.interfaces():
            try:
                addresses = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addresses:
                    for addr_info in addresses[netifaces.AF_INET]:
                        ip = addr_info.get('addr')
                        netmask = addr_info.get('netmask')
                        if ip and netmask and not ip.startswith('127.'):
                            try:
                                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                networks.append({
                                    'interface': interface,
                                    'network': network,
                                    'ip': ip
                                })
                            except:
                                continue
            except:
                continue
        return networks
    
    def get_vendor_info(self, mac_address):
        """Get vendor information from MAC address (simplified)"""
        # This is a basic implementation. For full vendor lookup,
        # you'd need a MAC address vendor database
        mac_prefixes = {
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '52:54:00': 'QEMU',
            '00:0c:29': 'VMware',
            '00:1c:42': 'Parallels',
            'dc:a6:32': 'Raspberry Pi',
            'b8:27:eb': 'Raspberry Pi',
            '28:cd:c1': 'Apple',
            'ac:de:48': 'Apple',
            '00:1b:63': 'Apple',
        }
        
        mac_prefix = mac_address[:8].lower()
        return mac_prefixes.get(mac_prefix, 'Unknown')
    
    def ping_host(self, ip):
        """Ping a single host to check if it's alive"""
        try:
            # Use appropriate ping command based on OS
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '-w', '500', str(ip)]  # Reduced timeout
            else:
                cmd = ['ping', '-c', '1', '-W', '1', str(ip)]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)  # Reduced timeout
            return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            return False
    
    def get_hostname(self, ip):
        """Get hostname for an IP address"""
        try:
            # Set socket timeout to prevent hanging
            socket.setdefaulttimeout(2)
            hostname = socket.gethostbyaddr(str(ip))[0]
            return hostname
        except (socket.timeout, socket.herror, socket.gaierror, Exception):
            return "Unknown"
        finally:
            socket.setdefaulttimeout(None)  # Reset to default
    
    def get_mac_address(self, ip):
        """Get MAC address for an IP using ARP table"""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a', str(ip)], 
                                      capture_output=True, text=True, timeout=3)  # Reduced timeout
                if result.returncode == 0:
                    # Parse Windows ARP output
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if str(ip) in line:
                            # Extract MAC address using regex
                            mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                            if mac_match:
                                return mac_match.group(0).replace('-', ':').upper()
            else:
                # For Linux/Unix systems
                result = subprocess.run(['arp', '-n', str(ip)], 
                                      capture_output=True, text=True, timeout=3)  # Reduced timeout
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if str(ip) in line and 'incomplete' not in line.lower():
                            parts = line.split()
                            if len(parts) >= 3:
                                mac = parts[2]
                                if ':' in mac and len(mac) == 17:
                                    return mac.upper()
            return "Unknown"
        except (subprocess.TimeoutExpired, Exception):
            return "Unknown"
    
    def get_open_ports(self, ip, common_ports=None):
        """Scan for common open ports"""
        if common_ports is None:
            common_ports = [22, 53, 80, 443, 3389, 5900]  # Reduced port list for speed
        
        open_ports = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)  # Very quick timeout
                result = sock.connect_ex((str(ip), port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                continue
        
        return open_ports
    
    def scan_device(self, ip, interface_name):
        """Scan a single device and gather information"""
        try:
            if not self.ping_host(ip):
                return None
            
            # Use threading for parallel information gathering
            hostname = self.get_hostname(ip)
            mac_address = self.get_mac_address(ip)
            vendor = self.get_vendor_info(mac_address) if mac_address != "Unknown" else "Unknown"
            open_ports = self.get_open_ports(ip)
            
            device_info = {
                'ip': str(ip),
                'hostname': hostname,
                'mac_address': mac_address,
                'vendor': vendor,
                'interface': interface_name,
                'open_ports': open_ports,
                'response_time': self.measure_response_time(ip)
            }
            
            with self.lock:
                self.devices.append(device_info)
            
            return device_info
        except Exception as e:
            # Skip problematic IPs
            return None
    
    def measure_response_time(self, ip):
        """Measure response time to host"""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Reduced timeout
            result = sock.connect_ex((str(ip), 80))
            sock.close()
            if result == 0:
                return round((time.time() - start_time) * 1000, 2)
            else:
                return "N/A"
        except Exception:
            return "N/A"
    
    def scan_network(self, max_threads=30):  # Reduced default threads
        """Scan all devices on local networks"""
        self.console.print(Panel.fit("🔍 Network Device Discovery", style="bold blue"))
        
        networks = self.get_local_networks()
        if not networks:
            self.console.print("[red]No local networks found![/red]")
            return
        
        # Limit scan to reasonable subnet sizes to avoid hanging
        total_hosts = 0
        scan_networks = []
        for net_info in networks:
            network = net_info['network']
            # Skip very large networks to prevent hanging
            if network.num_addresses > 512:  # Skip networks larger than /23
                self.console.print(f"[yellow]Skipping large network: {network} (too many hosts)[/yellow]")
                continue
            scan_networks.append(net_info)
            total_hosts += len(list(network.hosts()))
        
        if total_hosts == 0:
            self.console.print("[yellow]No suitable networks to scan found![/yellow]")
            return
            
        self.console.print(f"[cyan]Scanning {total_hosts} hosts across {len(scan_networks)} networks...[/cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Scanning hosts...", total=total_hosts)
            completed = 0
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {}
                
                for network_info in scan_networks:
                    network = network_info['network']
                    interface_name = network_info['interface']
                    
                    self.console.print(f"[cyan]Scanning network: {network} on interface {interface_name}[/cyan]")
                    
                    for ip in network.hosts():
                        future = executor.submit(self.scan_device, ip, interface_name)
                        futures[future] = str(ip)
                
                # Process completed futures with timeout
                for future in as_completed(futures, timeout=60):  # 60 second total timeout
                    try:
                        ip = futures[future]
                        result = future.result(timeout=5)  # 5 second per-future timeout
                        completed += 1
                        progress.update(task, advance=1)
                        
                        if result:
                            progress.update(task, description=f"Found: {result['ip']} ({result['hostname']})")
                        else:
                            progress.update(task, description=f"Scanned: {ip}")
                            
                    except Exception as e:
                        completed += 1
                        progress.update(task, advance=1)
                        continue
        
        # Add localhost information
        try:
            localhost_info = {
                'ip': '127.0.0.1',
                'hostname': socket.gethostname(),
                'mac_address': 'N/A (Localhost)',
                'vendor': 'N/A',
                'interface': 'lo',
                'open_ports': [],
                'response_time': 0.1
            }
            self.devices.append(localhost_info)
        except:
            pass
    
    def display_results(self):
        """Display results in a beautiful table"""
        if not self.devices:
            self.console.print("[red]No devices found on the network![/red]")
            return
        
        # Sort devices by IP address
        self.devices.sort(key=lambda x: ipaddress.IPv4Address(x['ip']))
        
        # Create table
        table = Table(title="🌐 Network Devices Discovered", show_header=True, header_style="bold magenta")
        table.add_column("IP Address", style="cyan", no_wrap=True)
        table.add_column("Hostname", style="green")
        table.add_column("MAC Address", style="yellow")
        table.add_column("Vendor", style="blue")
        table.add_column("Interface", style="red")
        table.add_column("Open Ports", style="purple")
        table.add_column("Response (ms)", style="bright_black")
        
        for device in self.devices:
            ports_str = ', '.join(map(str, device['open_ports'][:3]))  # Show max 3 ports
            if len(device['open_ports']) > 3:
                ports_str += '...'
            if not ports_str:
                ports_str = "None detected"
            
            response_time = str(device['response_time']) if device['response_time'] != "N/A" else "N/A"
            
            table.add_row(
                device['ip'],
                device['hostname'][:25] + "..." if len(device['hostname']) > 25 else device['hostname'],
                device['mac_address'],
                device['vendor'][:15] + "..." if len(device['vendor']) > 15 else device['vendor'],
                device['interface'],
                ports_str,
                response_time
            )
        
        self.console.print(table)
        
        # Display summary
        summary = Panel(
            f"[bold green]Scan Complete![/bold green]\n"
            f"Total devices found: {len(self.devices)}\n"
            f"Active hosts: {len([d for d in self.devices if d['ip'] != '127.0.0.1'])}\n"
            f"Unique vendors: {len(set(d['vendor'] for d in self.devices if d['vendor'] != 'Unknown'))}"
        )
        self.console.print(summary)


def main():
    parser = argparse.ArgumentParser(description="Discover devices on the local network")
    parser.add_argument("--threads", "-t", type=int, default=30, 
                       help="Number of threads to use for scanning (default: 30)")
    parser.add_argument("--quick", "-q", action="store_true",
                       help="Quick scan with minimal port checking")
    parser.add_argument("--timeout", type=int, default=1,
                       help="Ping timeout in seconds (default: 1)")
    
    args = parser.parse_args()
    
    try:
        scanner = NetworkScanner()
        
        # Adjust settings for quick scan
        if args.quick:
            # Override port scanning for speed
            scanner.get_open_ports = lambda ip, ports=None: []  # Skip port scanning
        
        scanner.scan_network(max_threads=args.threads)
        scanner.display_results()
    except KeyboardInterrupt:
        scanner.console.print("\n[red]Scan interrupted by user[/red]")
    except Exception as e:
        scanner.console.print(f"[red]Error: {str(e)}[/red]")


if __name__ == "__main__":
    main()