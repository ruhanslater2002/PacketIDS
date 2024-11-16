import argparse
from ids import IntrusionDetectionSystem


class Main:
    def __init__(self, scan_threshold: int, time_window: int, interface: str):
        self.IntrusionDetectionSystem: IntrusionDetectionSystem = IntrusionDetectionSystem(scan_threshold, time_window)
        self.interface = interface  # Store the interface in the instance

    def start(self) -> None:
        print(f"Using interface: {self.interface}")
        self.IntrusionDetectionSystem.scan()


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
        parser.error("Scan threshold must be a positive integer.")
    if args.time_window <= 0:
        parser.error("Time window must be a positive integer.")
    return args


if __name__ == '__main__':
    print(logo())  # Print the logo by calling the logo function
    args = parse_arguments()
    # Initialize the Main class with the parsed arguments
    Main(args.scan_threshold, args.time_window, args.interface).start()
