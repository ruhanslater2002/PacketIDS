import logging
from termcolor import colored


class ConsoleLogger:
    def __init__(self, logger_name: str):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG)
        console_handler: logging.StreamHandler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        formatter: logging.Formatter = logging.Formatter('[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s')
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def info(self, message: str) -> None:
        return self.logger.info("[" + colored("+", "green") + "] " + message)

    def warning(self, message: str) -> None:
        return self.logger.warning("[" + colored("*", "yellow") + "] " + message)

    def error(self, message: str) -> None:
        return self.logger.error("[" + colored("-", "red") + "] " + message)