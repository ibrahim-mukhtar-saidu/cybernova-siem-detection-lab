import pytest

from config_loader import ConfigError, load_config, load_rule, load_yaml


def test_load_yaml_valid_file(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("key: value\nnested:\n  a: 1\n", encoding="utf-8")

    data = load_yaml(config_file)

    assert data == {"key": "value", "nested": {"a": 1}}


def test_load_yaml_missing_file_raises_config_error(tmp_path):
    missing = tmp_path / "missing.yaml"

    with pytest.raises(ConfigError, match="not found"):
        load_yaml(missing)


def test_load_yaml_invalid_syntax_raises_config_error(tmp_path):
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text("key: [unterminated", encoding="utf-8")

    with pytest.raises(ConfigError, match="invalid YAML"):
        load_yaml(bad_file)


def test_load_yaml_non_mapping_top_level_raises_config_error(tmp_path):
    list_file = tmp_path / "list.yaml"
    list_file.write_text("- one\n- two\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="mapping"):
        load_yaml(list_file)


def test_load_yaml_scalar_top_level_raises_config_error(tmp_path):
    scalar_file = tmp_path / "scalar.yaml"
    scalar_file.write_text("just_a_string\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="mapping"):
        load_yaml(scalar_file)


def test_load_yaml_empty_file_raises_config_error(tmp_path):
    empty_file = tmp_path / "empty.yaml"
    empty_file.write_text("", encoding="utf-8")

    with pytest.raises(ConfigError, match="mapping"):
        load_yaml(empty_file)


def test_load_yaml_directory_given_as_file_raises(tmp_path):
    directory = tmp_path / "a_directory.yaml"
    directory.mkdir()

    with pytest.raises(ConfigError):
        load_yaml(directory)


def test_load_config_with_explicit_path(tmp_path):
    config_file = tmp_path / "siem_config.yaml"
    config_file.write_text(
        "project:\n  name: Test\nrisk:\n  levels:\n    LOW: 10\n",
        encoding="utf-8",
    )

    config = load_config(config_file)

    assert config["project"]["name"] == "Test"
    assert config["risk"]["levels"]["LOW"] == 10


def test_load_rule_with_required_keys(tmp_path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(
        "threshold: 5\nseverity: HIGH\nmitre: T1110 - Brute Force\n",
        encoding="utf-8",
    )

    rule = load_rule(rule_file)

    assert rule["threshold"] == 5
    assert rule["severity"] == "HIGH"
    assert rule["mitre"] == "T1110 - Brute Force"


def test_load_rule_missing_required_keys_raises_config_error(tmp_path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text("threshold: 5\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="missing required keys"):
        load_rule(rule_file)


def test_load_rule_missing_all_required_keys_raises_config_error(tmp_path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text("name: Some Rule\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="missing required keys"):
        load_rule(rule_file)


def test_load_rule_allows_extra_keys(tmp_path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(
        "threshold: 5\nseverity: HIGH\nmitre: T1110\nname: Extra\nid: RULE-999\n",
        encoding="utf-8",
    )

    rule = load_rule(rule_file)

    assert rule["name"] == "Extra"
    assert rule["id"] == "RULE-999"


def test_load_rule_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_rule(tmp_path / "missing_rule.yaml")
