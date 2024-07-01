
# Pathfinder

## Description

A Python-based network segmentation testing tool that performs ICMP, DNS, and TCP SYN scans to verify network segmentation and reachability across specified subnets. Supports detailed result display and summary generation with CLI flags.

## Features

- Perform various ICMP tests (Echo, Timestamp, Address Mask, Router Solicitation)
- Perform DNS resolution tests
- Perform TCP SYN scan on common ports
- Generates a summary of reachable hosts across subnets
- Optionally display detailed results for reachable hosts
- Saves results to CSV files

## Requirements

- Python 3.x
- psutil
- pandas
- rich

## Installation

Install the required Python packages using pip:

```sh
pip install psutil pandas rich
```

## Usage

### Command-line Arguments

- `--range`: Single range to test (e.g., `192.168.1.0/24`)
- `--range-list`: File with list of ranges to test
- `--source`: Network adapter to determine where access tests are executed from (e.g., `eth0`)
- `--detailed`, `-d`: Show detailed test results (optional)

### Examples

1. Test a single range and display detailed results:

```sh
python3 segmentation.py --range 192.168.1.0/24 --source eth0 --detailed
```

2. Test multiple ranges from a file and display summary only:

```sh
python3 segmentation.py --range-list ranges.txt --source eth0
```

### Output

- Results are saved to CSV files in the `results` directory.
- Summary of scan results is displayed in the console.
- Detailed test results are displayed if the `--detailed` flag is specified.

## License

This project is licensed under the MIT License.
