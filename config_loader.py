import yaml


CONFIG_FILE = "config/siem_config.yaml"


def load_config():
    with open(CONFIG_FILE, "r") as file:
        return yaml.safe_load(file)
