import streamlit as st
import hashlib
from cryptography.fernet import Fernet, InvalidToken
import json
import os

# Path to store the encryption key
KEY_FILE = "key.key"

# Load or generate the encryption key
def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

# Load the encryption key
KEY = load_or_generate_key()
cipher = Fernet(KEY)

# In-memory data storage (dictionary)
stored_data = {}  # {"encrypted_text": {"encrypted_text": "xyz", "passkey": "hashed"}}
failed_attempts = 0

# JSON file for persistence
DATA_FILE = "secure_data.json"

# Load data from JSON file on app startup
def load_data():
    global stored_data
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            stored_data = json.load(file)
    else:
        stored_data = {}

# Save data to JSON file
def save_data():
    with open(DATA_FILE, "w") as file:
        json.dump(stored_data, file)

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode('utf-8')).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode('utf-8')).decode('utf-8')

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    # Debugging: Print the hashed passkey
    print(f"Generated Hashed Passkey: {hashed_passkey}")

    # Check if the encrypted text exists in stored_data
    if encrypted_text not in stored_data:
        st.error("❌ Encrypted text not found!")
        return None

    stored_entry = stored_data[encrypted_text]
    stored_hashed_passkey = stored_entry["passkey"]
    print(f"Stored Hashed Passkey: {stored_hashed_passkey}")

    if hashed_passkey != stored_hashed_passkey:
        st.error("❌ Incorrect passkey!")
        failed_attempts += 1
        return None

    try:
        # Decrypt the text
        decrypted_text = cipher.decrypt(encrypted_text.encode('utf-8')).decode('utf-8')
        failed_attempts = 0  # Reset failed attempts on success
        return decrypted_text
    except InvalidToken as e:
        st.error(f"❌ Decryption failed: Invalid token.")
        return None
    except Exception as e:
        st.error(f"❌ Decryption failed: {e}")
        return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Load data at app startup
load_data()

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            save_data()  # Save data to JSON file
            st.success("✅ Data stored securely!")
            st.write(f"Encrypted Text: {encrypted_text}")  # Display the encrypted text for reference
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            try:
                decrypted_text = decrypt_data(encrypted_text, passkey)

                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")

                    if failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                        st.session_state["redirect_to_login"] = True
                        st.rerun()
            except Exception as e:
                st.error(f"❌ Invalid encrypted text or decryption failed: {e}")
        else:
            st.error("⚠️ Both fields are required!")

    # Redirect to login page if too many failed attempts
    if st.session_state.get("redirect_to_login", False):
        choice = "Login"
        st.session_state["redirect_to_login"] = False

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo, replace with proper auth
            failed_attempts = 0  # Reset failed attempts
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.rerun()
        else:
            st.error("❌ Incorrect password!")