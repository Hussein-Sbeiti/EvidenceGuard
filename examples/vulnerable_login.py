import sqlite3

db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE users (username TEXT, password TEXT)")
db.execute(
    "INSERT INTO users VALUES (?, ?)",
    ("admin", "school-project-password"),
)

username = input("Username: ")
password = input("Password: ")

# Intentionally vulnerable: user input is inserted directly into SQL.
query = (
    f"SELECT username FROM users "
    f"WHERE username = '{username}' AND password = '{password}'"
)
result = db.execute(query).fetchone()

if result:
    print("cracked code!")
else:
    print("Access denied")
