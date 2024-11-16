class TrafficLogManager:
    def __init__(self):
        self.traffic_logs: list[dict] = []  # List to store logs for each source IP

    def get_log(self, source_ip: str) -> dict:
        for traffic_log in self.traffic_logs:
            if traffic_log['ip'] == source_ip:
                return traffic_log
        return self.create_log(source_ip)

    def create_log(self, source_ip: str) -> dict:
        traffic_log = {'ip': source_ip, 'timestamps': [], 'ports': set()}
        self.traffic_logs.append(traffic_log)
        return traffic_log

    def update_log(self, log: dict, current_time: float, dest_port: int) -> None:
        log['timestamps'].append(current_time)
        log['ports'].add(dest_port)
        log['timestamps'] = [
            timestamp for timestamp in log['timestamps']
            if current_time - timestamp <= 60  # assuming a default time window of 60s for simplicity
        ]
