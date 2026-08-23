# INTENTIONALLY VULNERABLE TEST FIXTURE
import pickle

user_uploaded_bytes = input("Serialized data: ").encode()
obj = pickle.loads(user_uploaded_bytes)
print(obj)
