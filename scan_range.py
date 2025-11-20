#!/usr/bin/env python3
"""
Quick network scanner for specific IP ranges
Scans 10.9.0.0/24 through 10.9.10.0/24
"""

import subprocess
import socket
import ipaddress
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

console = Console()
devices = []

def ping_host(ip):
    """Ping a single host to check if it's alive"""
    try:
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '1', '-w', '500', str(ip)]
        else:
            cmd = ['ping', '-c', '1', '-W', '1', str(ip)]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        return result.returncode == 0
    except:
        return False

def get_hostname(ip):
    """Get hostname for an IP address"""
    try:
        socket.setdefaulttimeout(1)
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname
    except:
        return "Unknown"
    finally:
        socket.setdefaulttimeout(None)

def scan_ip(ip):
    """Scan a single IP address"""
    if ping_host(ip):
        hostname = get_hostname(ip)
        devices.append({'ip': str(ip), 'hostname': hostname})
        return {'ip': str(ip), 'hostname': hostname}
    return None

def main():
    console.print(Panel.fit("Network Scanner - 10.9.0.0/24 to 10.9.10.0/24", style="bold blue"))
    
    # Generate IP ranges: 10.9.0.0/24 through 10.9.10.0/24
    all_ips = []
    for third_octet in range(20, 40):  # 0 to 10 inclusive #I will change this
        network = ipaddress.IPv4Network(f"10.9.{third_octet}.0/24")
        all_ips.extend(list(network.hosts()))
    
    total_ips = len(all_ips)
    console.print(f"[cyan]Scanning {total_ips} IP addresses across 11 subnets...[/cyan]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Scanning...", total=total_ips)
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_ip, ip): ip for ip in all_ips}
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=3)
                    if result:
                        progress.update(task, description=f"Found: {result['ip']} ({result['hostname']})")
                except:
                    pass
                progress.update(task, advance=1)
    
    # Display results
    if not devices:
        console.print("[red]No devices found![/red]")
        return
    
    # Sort by IP
    devices.sort(key=lambda x: ipaddress.IPv4Address(x['ip']))
    
    # Create table
    table = Table(title="Network Devices Found", show_header=True, header_style="bold magenta")
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("Hostname", style="green")
    
    for device in devices:
        table.add_row(device['ip'], device['hostname'])
    
    console.print(table)
    console.print(f"\n[bold green]Found {len(devices)} active devices[/bold green]")

if __name__ == "__main__":
    main()
