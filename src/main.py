import argparse
from ids import IntrusionDetectionSystem


class Main:
    def __init__(self, scan_threshold: int, time_window: int):
        self.logo = """
 .----------------.  .----------------.  .----------------. 
| .--------------. || .--------------. || .--------------. |
| |     _____    | || |  ________    | || |    _______   | |
| |    |_   _|   | || | |_   ___ `.  | || |   /  ___  |  | |
| |      | |     | || |   | |   `. | | || |  |  (__ |_|  | |
| |      | |     | || |   | |    | | | || |   '.___`-.   | |
| |     _| |_    | || |  _| |___.' | | || |  |`|____) |  | |
| |    |_____|   | || | |________.'  | || |  |_______.'  | |
| |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------' 

        """
        # Print logo without extra indentation
        print(self.logo)
        self.IntrusionDetectionSystem: IntrusionDetectionSystem = IntrusionDetectionSystem(scan_threshold, time_window)

    def start(self) -> None:
        self.IntrusionDetectionSystem.scan()


def parse_arguments():
    """Parse command-line arguments with validation."""
    parser = argparse.ArgumentParser(description="Start Intrusion Detection System with custom thresholds.")
    parser.add_argument('-st', '--scan-threshold', type=int, default=20,
                        help="Threshold for port scan detection (default: 20)")
    parser.add_argument('-tw', '--time-window', type=int, default=10,
                        help="Time window in seconds for scan detection (default: 10)")
    args = parser.parse_args()
    # Validate that the arguments are positive integers
    if args.scan_threshold <= 0:
        parser.error("Scan threshold must be a positive integer.")
    if args.time_window <= 0:
        parser.error("Time window must be a positive integer.")
    return args


if __name__ == '__main__':
    args = parse_arguments()
    # Initialize the Main class with the parsed arguments
    Main(args.scan_threshold, args.time_window).start()
