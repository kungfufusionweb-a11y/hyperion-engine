import os
import pickle
import yaml

API_KEY = "sk-live-abc123xyz789"

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

def run_backup(cmd):
    os.system(cmd)

def load_data(raw_bytes):
    return pickle.loads(raw_bytes)

def load_config(raw_data):
    return yaml.load(raw_data)
