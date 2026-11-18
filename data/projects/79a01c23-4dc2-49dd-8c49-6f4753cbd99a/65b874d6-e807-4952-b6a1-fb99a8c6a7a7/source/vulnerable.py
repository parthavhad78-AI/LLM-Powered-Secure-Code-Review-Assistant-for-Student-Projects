import sqlite3
import subprocess
import hashlib

DB = "users.db"

def login(username, password):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)

    user = cursor.fetchone()

    # Weak password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()

    if user:
        print("Login successful for " + username)
        return True

    return False


def search_file(filename):
    # Command injection vulnerability
    command = "cat " + filename
    result = subprocess.check_output(command, shell=True)

    return result.decode()


def get_user_profile(user_id):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    # Another SQL injection
    cursor.execute("SELECT * FROM profiles WHERE id = " + user_id)

    return cursor.fetchone()


def save_password(password):
    # Hardcoded secret
    API_KEY = "sk_test_123456789_EXAMPLE_SECRET_KEY"

    # Insecure plaintext password storage
    with open("passwords.txt", "a") as file:
        file.write(password + "\n")

    return API_KEY


def calculate_discount(price, discount):
    # Logic error: discount can produce negative prices
    final_price = price - discount * price

    return final_price


def process_user(username):
    # Missing validation
    if username:
        print("Processing user:", username

    return True


def admin_action(user):
    # Broken authorization logic
    if user["role"] == "admin" or True:
        print("Admin action executed")
        return True

    return False


if __name__ == "__main__":
    username = input("Username: ")
    password = input("Password: ")

    login(username, password)

    print(search_file("test.txt"))