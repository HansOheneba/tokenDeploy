from flask import Flask, request, jsonify, session
from flask_mysqldb import MySQL
import bcrypt
import uuid
import os
from datetime import datetime
from dotenv import load_dotenv
import pyffx
import re
from MySQLdb import IntegrityError
import logging

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")  # Use an environment variable

# MySQL Configuration
app.config["MYSQL_HOST"] = os.getenv("MYSQL_HOST")
app.config["MYSQL_USER"] = os.getenv("MYSQL_USER")
app.config["MYSQL_PASSWORD"] = os.getenv("MYSQL_PASSWORD")
app.config["MYSQL_DB"] = os.getenv("MYSQL_DB")

mysql = MySQL(app)

# Secret key for encryption (should be securely stored)
FPE_SECRET_KEY = os.getenv("FPE_SECRET_KEY", "secret_key")

# Configure logging
logging.basicConfig(level=logging.DEBUG)


# Generate a secure token
def generate_token():
    return uuid.uuid4().hex


# Function to log events
def log_event(client_id, event_type, details):
    cur = mysql.connection.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute(
        "INSERT INTO logs (client_id, event_type, details, timestamp) VALUES (%s, %s, %s, %s)",
        (client_id, event_type, details, timestamp),
    )
    mysql.connection.commit()
    cur.close()


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

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT id, password_hash FROM clients WHERE client_id = %s", (client_id,)
    )
    user = cur.fetchone()

    if user and check_password(user[1], password):
        session["client_id"] = user[0]
        log_event(user[0], "login_success", "Client logged in successfully")
        cur.close()
        return jsonify({"message": "Login successful"})

    log_event(None, "failed_login", f"Failed login attempt for client_id: {client_id}")
    cur.close()
    return jsonify({"error": "Invalid credentials"}), 401


# Logout
@app.route("/logout", methods=["POST"])
def logout():
    session.pop("client_id", None)
    return jsonify({"message": "Logged out successfully"})


# Tokenization Endpoint
@app.route("/tokenize", methods=["POST"])
def tokenize():
    if "client_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    client_id = session["client_id"]
    ghana_card_number = data.get("ghana_card_number")
    phone_number = data.get("phone_number")

    if not ghana_card_number or not phone_number:
        return jsonify({"error": "Missing required fields"}), 400

    cur = mysql.connection.cursor()

    # Check if user exists
    logging.debug("Checking if user exists")
    cur.execute(
        "SELECT id FROM ghana_card_data WHERE ghana_card_number = %s AND phone_number = %s",
        (ghana_card_number, phone_number),
    )
    result = cur.fetchone()
    if not result:
        cur.close()
        return jsonify({"error": "No matching record found for that input"}), 404

    ghana_card_id = result[0]
    tokens = {}

    # List of all fields in the ghana_card_data table
    fields = [
        "ghana_card_number",
        "first_name",
        "middle_name",
        "last_name",
        "date_of_birth",
        "place_of_birth",
        "nationality",
        "ethnicity",
        "marital_status",
        "mother_name",
        "father_name",
        "email",
        "gender",
        "address",
        "phone_number",
    ]

    # Generate tokens for each field
    for field in fields:
        logging.debug(f"Processing field: {field}")

        cur.execute(
            f"SELECT {field} FROM ghana_card_data WHERE id = %s", (ghana_card_id,)
        )
        value_result = cur.fetchone()
        if not value_result or not value_result[0]:
            logging.warning(f"Field {field} is missing or empty in the database")
            tokens[field] = None  # If field doesn't exist, return null
            continue

        field_value = value_result[0]
        logging.debug(f"Field {field} value: {field_value}")
        try:
            token = encrypt_value(field_value, client_id, field)
            tokens[field] = token
        except Exception as e:
            logging.error(f"Error encrypting field {field}: {e}")
            tokens[field] = None

        # Store token in the database
        try:
            logging.debug(f"Inserting token for field: {field}")
            cur.execute(
                "INSERT INTO tokens (client_id, ghana_card_id, field_name, token, created_at) VALUES (%s, %s, %s, %s, %s)",
                (client_id, ghana_card_id, field, token, datetime.now()),
            )
            mysql.connection.commit()
        except IntegrityError as e:
            logging.error(f"Error inserting token for field {field}: {e}")

    log_event(
        client_id,
        "tokenization_success",
        f"Client {client_id} successfully tokenized fields for Ghana Card {ghana_card_id}",
    )
    cur.close()
    return jsonify({"tokens": tokens}), 200


# Detokenization Endpoint
@app.route("/detokenize", methods=["POST"])
def detokenize():
    if "client_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    client_id = session["client_id"]
    tokens = data.get("tokens", {})

    if not tokens:
        return jsonify({"error": "Missing required fields"}), 400

    cur = mysql.connection.cursor()
    original_values = {}
    unauthorized_fields = []
    unauthorized_client_ids = set()

    for field, token in tokens.items():
        if not token:
            original_values[field] = None
            continue

        cur.execute(
            "SELECT client_id, ghana_card_id FROM tokens WHERE token = %s AND field_name = %s",
            (token, field),
        )
        result = cur.fetchone()
        if not result or result[0] != client_id:
            unauthorized_fields.append(field)
            if result:
                unauthorized_client_ids.add(result[0])
            continue

        ghana_card_id = result[1]

        # Retrieve original value from ghana_card_data
        cur.execute(
            f"SELECT {field} FROM ghana_card_data WHERE id = %s", (ghana_card_id,)
        )
        original_value = cur.fetchone()
        if field == "date_of_birth" and original_value:
            original_values[field] = original_value[0].strftime("%Y-%m-%d")
        else:
            original_values[field] = original_value[0] if original_value else None

    if unauthorized_fields:
        unauthorized_client_ids_str = ", ".join(map(str, unauthorized_client_ids))
        log_event(
            client_id,
            "detokenization_failed",
            f"Client {client_id} attempted to detokenize fields that belong to client {unauthorized_client_ids_str}. Fields: {', '.join(unauthorized_fields)}.",
        )
        cur.close()
        return (
            jsonify({"error": "You are unauthorized to view this data"}),
            403,
        )

    log_event(
        client_id,
        "detokenization_success",
        f"Client {client_id} successfully detokenized fields for Ghana Card {ghana_card_id}",
    )
    cur.close()
    return jsonify(original_values), 200


if __name__ == "__main__":
    app.run(debug=True)
