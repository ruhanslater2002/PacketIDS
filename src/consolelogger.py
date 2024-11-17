import logging
import os
from termcolor import colored


class ConsoleLogger:
    def __init__(self, logger_name: str):
        # Ensure the logs directory exists
        os.makedirs("logs", exist_ok=True)
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG)
        # Console handler
        console_handler: logging.StreamHandler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_formatter: logging.Formatter = logging.Formatter('[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s')
        console_handler.setFormatter(console_formatter)
        # File handler
        file_handler: logging.FileHandler = logging.FileHandler("logs/application.log")
        file_handler.setLevel(logging.DEBUG)
        file_formatter: logging.Formatter = logging.Formatter('[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s')
        file_handler.setFormatter(file_formatter)
        # Add handlers to the logger
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    def info(self, message: str) -> None:
        return self.logger.info("[" + colored("+", "green") + "] " + message)

    def warning(self, message: str) -> None:
        return self.logger.warning("[" + colored("*", "yellow") + "] " + message)

    def error(self, message: str) -> None:
        return self.logger.error("[" + colored("-", "red") + "] " + message)
