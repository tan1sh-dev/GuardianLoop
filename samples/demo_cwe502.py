# Intentionally vulnerable sample: CWE-502 insecure deserialization.
#
# pickle.loads() can execute arbitrary code via __reduce__.
# yaml.load() without SafeLoader can instantiate arbitrary objects.
#
# A correct patch must:
#   - Replace pickle with json for data exchange.
#   - Replace yaml.load() with yaml.safe_load().

import pickle
import yaml
import sys


def load_user_data_pickle(data_bytes):
    # VULNERABLE: pickle.loads on untrusted data enables arbitrary code execution
    # via the __reduce__ protocol.
    user_data = pickle.loads(data_bytes)
    return user_data


def load_config_yaml(yaml_string):
    # VULNERABLE: yaml.load without SafeLoader can instantiate arbitrary objects.
    config = yaml.load(yaml_string)
    return config


if __name__ == "__main__":
    # Simulate loading untrusted pickle data
    sample_data = pickle.dumps({"name": "alice", "role": "user"})
    print(f"Loaded pickle: {load_user_data_pickle(sample_data)}")

    # Simulate loading untrusted YAML
    yaml_str = "name: alice\nrole: admin"
    print(f"Loaded YAML: {load_config_yaml(yaml_str)}")
