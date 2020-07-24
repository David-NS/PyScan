import argparse
import math
import socket
import subprocess
import time
from multiprocessing import Manager, Pool
from multiprocessing.pool import ThreadPool

from utils import Color


def scan_port(ip_address: str, port: int, timeout: float, open_ports: list):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.connect((ip_address, port))
    except ConnectionError:
        pass  # print(f"Closed {port}")
    except socket.timeout:
        pass  # print(f"Timeout {port}")
    except OSError as e:
        print(f"{Color.CRED}ERROR! {ip_address}:{port} -> {str(e)}{Color.CEND}")
    else:
        open_ports.append(str(port))
        print(f"Open {Color.CVIOLET}{port}{Color.CEND}")
    finally:
        s.close()


def batch_process(ip_address: str, batch_threads: int, port_from: int, port_to: int, timeout: float, open_ports: list):
    pool = ThreadPool(processes=batch_threads)

    items = []
    for port in range(port_from, port_to):
        items.append((ip_address, port, timeout, open_ports))

    pool.starmap(scan_port, items)
    pool.close()
    pool.join()


def launch_scan(batch: int, batch_threads: int, ip_address: str, from_port: int, to_port: int, timeout: float):
    manager = Manager()
    open_ports = manager.list()

    batches = math.ceil(to_port / batch)

    pool = Pool(processes=batches)

    batch_from = from_port
    batch_to = batch

    items = []
    while batch_from <= to_port:
        items.append((ip_address, batch_threads, batch_from, batch_to, timeout, open_ports))
        batch_from += batch
        batch_to += batch if to_port - batch_from >= batch else to_port - batch_from + 1

    pool.starmap(batch_process, items)
    pool.close()
    pool.join()

    return open_ports


def main():
    parser = argparse.ArgumentParser(description='PyScanner - Fast python port scanner')

    parser.add_argument('-b', '--batch', help='Size of each set of ports that will spawn a subprocess', type=int,
                        default=2500)
    parser.add_argument('-th', '--batch-threads', help='Number of threads each batch will start', type=int, default=250)
    parser.add_argument('-fp', '--from-port', help='Port at which the scan will start', type=int, default=1)
    parser.add_argument('-tp', '--to-port', help='Port at which the scan will end', type=int, default=65535)
    parser.add_argument('-T', '--timeout', help='Timeout before considering a port closed', type=float, default=10)
    parser.add_argument('ip_address', help='IP address to scan ports from', type=str)
    parser.add_argument('nmap_command', help='Arguments for nmap', type=str, default=['-A', '-vvv'], nargs='*')

    config = parser.parse_args()

    print(f"{Color.CYELLOW}       _____        _____\n"
          "      |  __ \\      / ____|\n"
          "      | |__) |   _| (___   ___ __ _ _ __\n"
          "      |  ___/ | | |\\___ \\ / __/ _` | '_ \\\n"
          "      | |   | |_| |____) | (_| (_| | | | |\n"
          "      |_|    \\__, |_____/ \\___\\__,_|_| |_|\n"
          "              __/ |\n"
          "             |___/\n"
          f"Blazing-fast port scanner made with Python and ♥️{Color.CEND}\n"

          f"Launching PyScan scan of {config.ip_address} with:\n"
          f"  · Batch size of {config.batch}, with {config.batch_threads} threads per batch\n"
          f"  · Ports ranging from {config.from_port} to {config.to_port}\n"
          f"  · Timeout of {config.timeout} seconds\n")

    start_time = time.time()
    result = launch_scan(batch=config.batch,
                         batch_threads=config.batch_threads,
                         from_port=config.from_port,
                         to_port=config.to_port,
                         timeout=config.timeout,
                         ip_address=config.ip_address)

    print(f"\nScan finished, summary:\n"
          f"  · {round(time.time() - start_time)} seconds of execution\n"
          f"  · {len(result)} ports found open\n\n"
          f"Open ports: {', '.join(result)}\n")

    if result:
        nmap_command = ["nmap", *config.nmap_command, "-p", ','.join(result), config.ip_address]
        print(f"{Color.CBLUE}Launching nmap  with command: '{' '.join(nmap_command)}'{Color.CEND}\n")
        subprocess.run(nmap_command)
    else:
        print(f"{Color.CBLUE}No open ports found, nmap wont be executed{Color.CEND}")


if __name__ == '__main__':
    main()
