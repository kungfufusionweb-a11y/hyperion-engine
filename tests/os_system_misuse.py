# INTENTIONALLY VULNERABLE TEST FIXTURE
import os

user_input = input("Host to ping: ")
os.system("ping " + user_input)
