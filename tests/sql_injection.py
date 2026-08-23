# INTENTIONALLY VULNERABLE TEST FIXTURE
import sqlite3

conn = sqlite3.connect("example.db")
cursor = conn.cursor()
user_input = input("User ID: ")
cursor.execute(f"SELECT * FROM users WHERE id = '{user_input}'")
