import argparse
from ids import IntrusionDetectionSystem


class Main:
    def __init__(self, scan_threshold: int, time_window: int):
        self.IntrusionDetectionSystem: IntrusionDetectionSystem = IntrusionDetectionSystem(scan_threshold, time_window)

    def start(self) -> None:
        self.IntrusionDetectionSystem.scan()


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Start Intrusion Detection System with custom thresholds.")
    parser.add_argument('--scan-threshold', type=int, default=20, help="Threshold for port scan detection (default: 20)")
    parser.add_argument('--time-window', type=int, default=10, help="Time window in seconds for scan detection (default: 10)")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_arguments()
    # Initialize the Main class with the parsed arguments
    Main(args.scan_threshold, args.time_window).start()
