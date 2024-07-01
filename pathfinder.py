import argparse
import ipaddress
import subprocess
import psutil
import socket
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from datetime import datetime, timedelta
import os

# Function to check DNS resolution
def dns_resolution_test(host):
    try:
        resolved_name = socket.gethostbyaddr(host)[0]
        return host, 'DNS Resolution', True, resolved_name
    except socket.herror:
        return host, 'DNS Resolution', False, None

# Function to ping using ICMP Echo Request
def icmp_echo_test(host):
    try:
        response = subprocess.run(['ping', '-c', '1', '-W', '1', host],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        return host, 'ICMP Echo', response.returncode == 0, None
    except Exception as e:
        return host, 'ICMP Echo', False, None

# Function to ping using ICMP Timestamp Request
def icmp_timestamp_test(host):
    try:
        response = subprocess.run(['ping', '-c', '1', '-W', '1', '-T', 'ts', host],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        return host, 'ICMP Timestamp', response.returncode == 0, None
    except Exception as e:
        return host, 'ICMP Timestamp', False, None

# Function to ping using ICMP Address Mask Request
def icmp_address_mask_test(host):
    try:
        response = subprocess.run(['ping', '-c', '1', '-W', '1', '-T', 'mask', host],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        return host, 'ICMP Address Mask', response.returncode == 0, None
    except Exception as e:
        return host, 'ICMP Address Mask', False, None

# Function to ping using ICMP Router Solicitation Request
def icmp_router_solicitation_test(host):
    try:
        response = subprocess.run(['nmap', '-PR', '-sn', host],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        return host, 'ICMP Router Solicitation', "Host is up" in response.stdout.decode(), None
    except Exception as e:
        return host, 'ICMP Router Solicitation', False, None

# Function to perform TCP SYN scan on common ports
def tcp_syn_scan(host):
    common_ports = [80, 443, 22, 21, 23, 25, 110, 135, 139, 445, 3389]
    open_ports = []
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return host, 'TCP SYN Scan', bool(open_ports), open_ports

# Function to process a single range
def process_range(range_str):
    try:
        network = ipaddress.ip_network(range_str, strict=False)
        return [str(host) for host in network.hosts()]
    except ValueError as e:
        print(f"Invalid range: {range_str}")
        return []

# Function to get the IP range of a network adapter
def get_adapter_range(adapter):
    addrs = psutil.net_if_addrs().get(adapter)
    if not addrs:
        raise ValueError(f"No such adapter: {adapter}")
    
    for addr in addrs:
        if addr.family == socket.AF_INET:
            ip_net = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            return str(ip_net)
    
    raise ValueError(f"No IPv4 address found for adapter: {adapter}")

def create_status_table(source_range, current_range, test_name, completed_hosts, total_hosts, start_time):
    elapsed_time = datetime.now() - start_time
    estimated_total_time = (elapsed_time / completed_hosts) * total_hosts if completed_hosts > 0 else timedelta(seconds=0)
    remaining_time = estimated_total_time - elapsed_time
    progress_text = f"{completed_hosts}/{total_hosts} ({(completed_hosts / total_hosts) * 100:.2f}%)"
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Source Subnet", width=30)
    table.add_column("Current Subnet", width=30)
    table.add_column("Current Test", width=30)
    table.add_column("Progress", width=20)
    table.add_column("Elapsed Time", width=20)
    table.add_column("Remaining Time", width=20)
    table.add_row(source_range, current_range, test_name, progress_text, str(elapsed_time).split('.')[0], str(remaining_time).split('.')[0])
    return table

def update_status(live, source_range, current_range, test_name, completed_hosts, total_hosts, start_time):
    table = create_status_table(source_range, current_range, test_name, completed_hosts, total_hosts, start_time)
    live.update(Panel(table, title="Current Scan Status"))

def save_results(df, current_range):
    output_dir = "results"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{current_range.replace('/', '_')}_results.csv")
    df.to_csv(output_file, index=False)
    return output_file

def scan_subnet(source_range, current_range, hosts, tests, live, start_time):
    results = []
    for test in tests:
        test_name = test.__name__.replace('_test', '').replace('_', ' ').title()
        completed_hosts = 0
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(test, host): host for host in hosts}
            for future in futures:
                host, test_name, result, extra_info = future.result()
                status_icon = "✔️" if result else "❌"
                results.append((host, test_name, status_icon, extra_info))
                completed_hosts += 1
                update_status(live, source_range, current_range, test_name, completed_hosts, len(hosts), start_time)
    
    return results

# Main function to handle the arguments and start the tests
def main():
    parser = argparse.ArgumentParser(description="Advanced Segmentation Testing Tool")
    parser.add_argument('--range', type=str, help="Single range to test")
    parser.add_argument('--range-list', type=str, help="File with list of ranges to test")
    parser.add_argument('--source', type=str, required=True, help="Network adapter to determine where access tests are executed from (e.g., eth0)")
    parser.add_argument('--detailed', '-d', action='store_true', help="Show detailed test results")

    args = parser.parse_args()
    all_results = []
    hosts = []
    current_range = "N/A"

    if args.range:
        current_range = args.range
        hosts.extend(process_range(args.range))
    
    ranges = []
    if args.range_list:
        with open(args.range_list, 'r') as file:
            ranges = [range_str.strip() for range_str in file.readlines()]
    if not ranges and not args.range:
        print("No valid ranges provided")
        return

    try:
        source_range = get_adapter_range(args.source)
        print(f"Source subnet determined from adapter {args.source}: {source_range}")
    except ValueError as e:
        print(str(e))
        return

    console = Console()
    console.print(Markdown(f"# Starting tests from {source_range}"))

    tests = [dns_resolution_test, icmp_echo_test, icmp_timestamp_test, icmp_address_mask_test, icmp_router_solicitation_test]

    start_time = datetime.now()

    with Live(console=console, refresh_per_second=1) as live:
        for current_range in ranges:
            hosts = process_range(current_range)
            results = scan_subnet(source_range, current_range, hosts, tests, live, start_time)
            all_results.append((current_range, results))
            
            if results:
                df = pd.DataFrame(results, columns=['Host', 'Test', 'Result', 'Extra Info'])
                result_table = df.pivot(index='Host', columns='Test', values='Result').fillna('❌')
                
                # Save results to file
                output_file = save_results(df, current_range)
                console.print(f"Results saved to {output_file}")

    # Display final results
    summary_data = []

    for current_range, results in all_results:
        reachable_hosts = []
        for result in results:
            if result[1] != 'DNS Resolution' and result[2] == "✔️":
                reachable_hosts.append(result[0])
        reachable_count = len(set(reachable_hosts))
        total_hosts = len(process_range(current_range))
        summary_data.append((source_range, current_range, reachable_count, total_hosts))

        if args.detailed and reachable_hosts:
            detailed_results = [result for result in results if result[2] == "✔️"]
            if detailed_results:
                df = pd.DataFrame(detailed_results, columns=['Host', 'Test', 'Result', 'Extra Info'])
                result_table = df.pivot(index='Host', columns='Test', values='Result').fillna('❌')

                # Merge DNS resolution information
                if 'DNS Resolution' in result_table.columns:
                    result_table['DNS Resolution'] = df.set_index('Host')['Extra Info'].dropna()
                    result_table['DNS Resolution'] = result_table['DNS Resolution'].fillna('')

                # Display results using rich
                result_table_rich = Table(show_header=True, header_style="bold magenta")
                result_table_rich.add_column("Host", style="dim", width=20)
                for column in result_table.columns:
                    result_table_rich.add_column(column, width=20)
                for index, row in result_table.iterrows():
                    result_table_rich.add_row(index, *[row[col] for col in result_table.columns])

                console.print(Panel(result_table_rich, title=f"Test Results for {current_range}"))

    # Display summary
    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Source Subnet", style="dim", width=30)
    summary_table.add_column("Destination Subnet", style="dim", width=30)
    summary_table.add_column("Reachable Hosts", style="dim", width=20)
    summary_table.add_column("Total Hosts", style="dim", width=20)
    
    for source, dest, reachable, total in summary_data:
        reachable_icon = "✔️" if reachable > 0 else "❌"
        summary_table.add_row(source, dest, f"{reachable_icon} {reachable}", str(total))
    
    console.print(Panel(summary_table, title="Summary of Scan Results"))

if __name__ == "__main__":
    main()
