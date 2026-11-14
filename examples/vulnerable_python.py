"""Intentionally insecure scanner fixture. Read/scan this file; do not run it.

Historical YAML reference: CVE-2020-14343. That advisory concerns specific
PyYAML versions; a CVE mention does not confirm this file's applicability.
The other examples below illustrate weakness classes, not that CVE.
"""


def evaluate_input(user_input):
    return eval(user_input)


def load_untrusted_session(serialized_session):
    import pickle
    return pickle.loads(serialized_session)


def run_untrusted_command(user_command):
    import subprocess
    return subprocess.run(user_command, shell=True)


def load_untrusted_yaml(document):
    import yaml
    return yaml.load(document, Loader=yaml.FullLoader)


def demo_credential():
    password = "demo-only-not-a-real-password"
    return password
