import logging
import os


def get_logger(name="linuxaudit"):
    os.makedirs("logs", exist_ok=True)

    log_file = "logs/linux_audit.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

    return logging.getLogger(name)