"""Comparison fixture: expected to produce zero current heuristic matches."""

import json
import subprocess


def parse_input(user_input):
    return json.loads(user_input)


def run_fixed_tool(user_value):
    return subprocess.run(["echo", user_value], check=True, shell=False)


def find_user(connection, username):
    return connection.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
