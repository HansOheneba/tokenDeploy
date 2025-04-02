from flask import Flask, request, jsonify, session
import pymysql
import bcrypt
import uuid
import os
from datetime import datetime
from dotenv import load_dotenv
import pyffx
import re
import logging

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")  # Use an environment variable

# MySQL Configuration
db_config = {
    "host": os.getenv("MYSQL_HOST"),
    "user": os.getenv("MYSQL_USER"),
    "password": os.getenv("MYSQL_PASSWORD"),
    "database": os.getenv("MYSQL_DB"),
}

# Secret key for encryption (should be securely stored)
FPE_SECRET_KEY = os.getenv("FPE_SECRET_KEY", "secret_key")

# Configure logging
logging.basicConfig(level=logging.DEBUG)


# Generate a secure token
def generate_token():
    return uuid.uuid4().hex


# Function to log events
def log_event(client_id, event_type, details):
    connection = pymysql.connect(**db_config)
    cursor = connection.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO logs (client_id, event_type, details, timestamp) VALUES (%s, %s, %s, %s)",
        (client_id, event_type, details, timestamp),
    )
    connection.commit()
    cursor.close()
    connection.close()


# Hash Password
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()


# Verify Password
def check_password(stored_hash, password):
    return bcrypt.checkpw(password.encode(), stored_hash.encode())


# Function to generate a format-preserving encrypted token
def encrypt_value(value, client_id, field_name):
    # Convert value to string
    value = str(value)
    # Preprocess the value to remove non-alphabet characters
    value = re.sub(r"[^a-zA-Z0-9]", "", value)
    key = (FPE_SECRET_KEY + str(client_id) + field_name).encode("utf-8")
    cipher = pyffx.String(
        key,
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        length=len(value),
    )
    return cipher.encrypt(value)


# Function to decrypt a token back to original value
def decrypt_value(token, client_id, field_name):
    key = (FPE_SECRET_KEY + str(client_id) + field_name).encode("utf-8")
    cipher = pyffx.String(
        key,
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        length=len(token),
    )
    return cipher.decrypt(token)


# Client Login
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    client_id = data.get("client_id")
    password = data.get("password")

    connection = pymysql.connect(**db_config)
    cursor = connection.cursor()
    cursor.execute(
        "SELECT id, password_hash, category_id FROM clients WHERE client_id = %s",
        (client_id,),
    )
    user = cursor.fetchone()

    if user and check_password(user[1], password):
        session["client_id"] = user[0]
        session["category_id"] = user[2]  # Store category in session
        log_event(user[0], "login_success", "Client logged in successfully")
        cursor.close()
        connection.close()
        return jsonify({"message": "Login successful"})

    log_event(None, "failed_login", f"Failed login attempt for client_id: {client_id}")
    cursor.close()
    connection.close()
    return jsonify({"error": "Invalid credentials"}), 401


# Logout
@app.route("/logout", methods=["POST"])
def logout():
    session.pop("client_id", None)
    return jsonify({"message": "Logged out successfully"})


# Tokenize endpoint
@app.route("/tokenize", methods=["POST"])
def tokenize():
    if "client_id" not in session or "category_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    client_id = session["client_id"]
    category_id = session["category_id"]
    ghana_card_number = data.get("ghana_card_number")
    phone_number = data.get("phone_number")

    if not ghana_card_number or not phone_number:
        return jsonify({"error": "Missing required fields"}), 400

    connection = pymysql.connect(**db_config)
    cursor = connection.cursor()

    # Check if user exists
    cursor.execute(
        "SELECT id FROM ghana_card_data WHERE ghana_card_number = %s AND phone_number = %s",
        (ghana_card_number, phone_number),
    )
    result = cursor.fetchone()
    if not result:
        cursor.close()
        connection.close()
        return jsonify({"error": "No matching record found"}), 404

    ghana_card_id = result[0]
    tokens = {}

    # Check if tokens already exist for this client and Ghana Card
    cursor.execute(
        "SELECT field_name, token FROM tokens WHERE client_id = %s AND ghana_card_id = %s",
        (client_id, ghana_card_id),
    )
    existing_tokens = cursor.fetchall()

    if existing_tokens:
        # If tokens exist, return them
        for field_name, token in existing_tokens:
            tokens[field_name] = token
        log_event(
            client_id,
            "tokenization_success",
            f"Client {client_id} retrieved existing tokens for Ghana Card {ghana_card_id}",
        )
        cursor.close()
        connection.close()
        return jsonify({"tokens": tokens}), 200

    # Retrieve allowed fields for this category
    cursor.execute(
        "SELECT field_name FROM category_permissions WHERE category_id = %s",
        (category_id,),
    )
    allowed_fields = [row[0] for row in cursor.fetchall()]

    # Generate tokens for allowed fields only
    for field in allowed_fields:
        cursor.execute(
            f"SELECT {field} FROM ghana_card_data WHERE id = %s", (ghana_card_id,)
        )
        value_result = cursor.fetchone()
        if not value_result or not value_result[0]:
            tokens[field] = None  # If field doesn't exist, return null
            continue

        field_value = value_result[0]
        token = encrypt_value(field_value, client_id, field)
        tokens[field] = token

        # Store token in the database
        cursor.execute(
            "INSERT INTO tokens (client_id, ghana_card_id, field_name, token, created_at) VALUES (%s, %s, %s, %s, %s)",
            (client_id, ghana_card_id, field, token, datetime.now()),
        )
        connection.commit()

    log_event(
        client_id,
        "tokenization_success",
        f"Client {client_id} successfully tokenized fields for Ghana Card {ghana_card_id}",
    )
    cursor.close()
    connection.close()
    return jsonify({"tokens": tokens}), 200


# Detokenize endpoint
@app.route("/detokenize", methods=["POST"])
def detokenize():
    if "client_id" not in session or "category_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    client_id = session["client_id"]
    category_id = session["category_id"]
    tokens = data.get("tokens", {})

    if not tokens:
        return jsonify({"error": "Missing required fields"}), 400

    connection = pymysql.connect(**db_config)
    cursor = connection.cursor()

    # Retrieve allowed fields for this category
    cursor.execute(
        "SELECT field_name FROM category_permissions WHERE category_id = %s",
        (category_id,),
    )
    allowed_fields = {row[0] for row in cursor.fetchall()}

    original_values = {}
    unauthorized_fields = []

    for field, token in tokens.items():
        if not token:
            original_values[field] = None
            continue

        if field not in allowed_fields:
            unauthorized_fields.append(field)
            continue

        cursor.execute(
            "SELECT client_id, ghana_card_id FROM tokens WHERE token = %s AND field_name = %s",
            (token, field),
        )
        result = cursor.fetchone()
        if not result or result[0] != client_id:
            unauthorized_fields.append(field)
            continue

        ghana_card_id = result[1]

        # Retrieve original value
        cursor.execute(
            f"SELECT {field} FROM ghana_card_data WHERE id = %s", (ghana_card_id,)
        )
        original_value = cursor.fetchone()
        original_values[field] = (
            original_value[0].strftime("%Y-%m-%d")
            if field == "date_of_birth" and original_value
            else original_value[0] if original_value else None
        )

    if unauthorized_fields:
        log_event(
            client_id,
            "detokenization_failed",
            f"Client {client_id} attempted to detokenize unauthorized fields: {', '.join(unauthorized_fields)}",
        )
        cursor.close()
        connection.close()
        return (
            jsonify({"error": "You are unauthorized to view some requested fields"}),
            403,
        )

    log_event(
        client_id,
        "detokenization_success",
        f"Client {client_id} successfully detokenized fields for Ghana Card {ghana_card_id}",
    )
    cursor.close()
    connection.close()
    return jsonify(original_values), 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5002)
