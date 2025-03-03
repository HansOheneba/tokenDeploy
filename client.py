import mysql.connector
import bcrypt

# Database connection details
db_config = {
    "host": "srv1567.hstgr.io",
    "user": "u941080935_ciso",
    "password": "Cyberpunk..2077",
    "database": "u941080935_ciso",
}


# Function to hash passwords
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed


# Function to insert a client
def insert_client(client_id, name, password):
    hashed_password = hash_password(password)

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        query = "INSERT INTO clients (client_id, name, password_hash) VALUES (%s, %s, %s)"
        values = (client_id, name, hashed_password)

        cursor.execute(query, values)
        conn.commit()

        print(f"✅ Client '{name}' added successfully!")

    except mysql.connector.Error as err:
        print("❌ Failed to insert client:", err)

    finally:
        if "conn" in locals() and conn.is_connected():
            cursor.close()
            conn.close()


# Test Insert
if __name__ == "__main__":
    client_id = input("Enter Client ID: ")
    name = input("Enter Client Name: ")
    password = input("Enter Client Password: ")

    insert_client(client_id, name, password)
