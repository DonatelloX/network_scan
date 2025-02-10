This Python script is an advanced network scanner designed to detect active devices on a local network. It efficiently retrieves network interfaces, scans for reachable hosts, and displays their IP, hostname, MAC address, and vendor information. The script is optimized for cross-platform compatibility (Windows, Linux, macOS) and uses multithreading for fast scanning.

# Installation
To ensure all required libraries are installed, you can run the following command before executing the script:

```pip install psutil tqdm mac-vendor-lookup tabulate```

Alternatively, you can use the script’s built-in installation feature:

```python network_scan.py --install```

This will automatically check and install any missing dependencies.

# Command-Line Interface
The script supports several command-line options:

```--install``` → Installs missing dependencies and exits.

```-i```, --interface → Specifies the network interface to use (e.g., eth0, Wi-Fi).

*Example usage:*

```python network_scan.py -i eth0```

If no interface is specified, the script lists available interfaces and allows selection.
