import argparse
import sys
from ids import IntrusionDetectionSystem


class Main:
    def __init__(self, scan_threshold: int, time_window: int, interface: str):
        # Try to initialize IntrusionDetectionSystem and catch any initialization errors
        try:
            self.IntrusionDetectionSystem: IntrusionDetectionSystem = IntrusionDetectionSystem(scan_threshold,
                                                                                               time_window, interface)
        except Exception as e:
            print(f"Error initializing Intrusion Detection System: {e}")
            sys.exit(1)  # Exit the program with error status
        self.interface = interface  # Store the interface in the instance

    def start(self) -> None:
        print(f"Using interface: {self.interface}")
        try:
            self.IntrusionDetectionSystem.scan()
        except Exception as e:
            print(f"Error during scan: {e}")
            sys.exit(1)  # Exit the program with error status


def logo():
    return r"""
            .___________    _________
            |   \______ \  /   _____/
            |   ||    |  \ \_____  \ 
            |   ||    `   \/        \
            |___/_______  /_______  /
                        \/        \/ 
                    """


def parse_arguments():
    """Parse command-line arguments with validation."""
    parser = argparse.ArgumentParser(description="Start Intrusion Detection System with custom thresholds.")
    parser.add_argument('-st', '--scan-threshold', type=int, default=20,
                        help="Threshold for port scan detection (default: 20)")
    parser.add_argument('-tw', '--time-window', type=int, default=10,
                        help="Time window in seconds for scan detection (default: 10)")
    parser.add_argument('-if', '--interface', type=str, default="eth0",  # Default interface is "eth0"
                        help="Network interface to use (default: eth0)")
    args: argparse.Namespace = parser.parse_args()
    # Validate that the arguments are positive integers
    if args.scan_threshold <= 0:
        print("Error: Scan threshold must be a positive integer.")
        sys.exit(1)
    if args.time_window <= 0:
        print("Error: Time window must be a positive integer.")
        sys.exit(1)
    # Interface validation (Basic check if the interface string is not empty)
    if not args.interface:
        print("Error: Network interface cannot be empty.")
        sys.exit(1)
    # You can add more specific network interface validation if needed
    # For example, checking if the interface exists on the system
    return args


if __name__ == '__main__':
    print(logo())  # Print the logo by calling the logo function
    try:
        args = parse_arguments()  # Parse arguments
        # Initialize the Main class with the parsed arguments
        Main(args.scan_threshold, args.time_window, args.interface).start()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
