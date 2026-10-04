import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path
from datetime import datetime, timezone
import json


# =========================
# SecureVault
# =========================

DATA_DIR = Path("securevault_data")
KEYS_DIR = DATA_DIR / "keys"
LOG_FILE = DATA_DIR / "audit_log.jsonl"
REGISTRY_FILE = DATA_DIR / "key_registry.json"

DATA_DIR.mkdir(exist_ok=True)
KEYS_DIR.mkdir(exist_ok=True)


st.set_page_config(
    page_title="SecureVault",
    page_icon="🔐",
    layout="centered"
)


# =========================
# Helper Functions
# =========================

def current_time():
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )


def audit(event, details=""):
    entry = {
        "time": current_time(),
        "event": event,
        "details": details
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")


# =========================
# Key Management Functions
# =========================

def save_registry(registry):
    REGISTRY_FILE.write_text(
        json.dumps(registry, indent=4),
        encoding="utf-8"
    )


def load_registry():
    if REGISTRY_FILE.exists():
        try:
            data = json.loads(
                REGISTRY_FILE.read_text(
                    encoding="utf-8"
                )
            )

            if isinstance(data, list):
                return data

        except json.JSONDecodeError:
            st.error("Could not read key registry.")

    # Create first key
    key_id = "KEY-001"
    key = Fernet.generate_key()

    (KEYS_DIR / f"{key_id}.key").write_bytes(key)

    registry = [
        {
            "key_id": key_id,
            "status": "ACTIVE",
            "created_at": current_time()
        }
    ]

    save_registry(registry)

    audit(
        "KEY_CREATED",
        f"{key_id} created"
    )

    return registry


def get_key(key_id):
    key_file = KEYS_DIR / f"{key_id}.key"

    if not key_file.exists():
        raise FileNotFoundError(
            f"Key {key_id} not found."
        )

    return key_file.read_bytes()


def get_active_key(registry):
    for item in registry:
        if item["status"] == "ACTIVE":
            return item["key_id"]

    return None


def rotate_key():
    registry = load_registry()

    # Retire current active key
    for item in registry:
        if item["status"] == "ACTIVE":
            item["status"] = "RETIRED"

    # Find next key number
    numbers = []

    for item in registry:
        try:
            numbers.append(
                int(item["key_id"].split("-")[1])
            )
        except (ValueError, IndexError):
            pass

    next_number = max(numbers, default=0) + 1
    new_id = f"KEY-{next_number:03d}"

    # Generate new key
    new_key = Fernet.generate_key()

    (KEYS_DIR / f"{new_id}.key").write_bytes(
        new_key
    )

    # Add new active key
    registry.append(
        {
            "key_id": new_id,
            "status": "ACTIVE",
            "created_at": current_time()
        }
    )

    save_registry(registry)

    audit(
        "KEY_ROTATED",
        f"{new_id} is now active"
    )

    return new_id
def revoke_key(key_id):
    registry = load_registry()

    for item in registry:

        if item["key_id"] == key_id:

            if item["status"] != "RETIRED":
                raise ValueError(
                    "Only retired keys can be revoked."
                )

            item["status"] = "REVOKED"

            save_registry(registry)

            audit(
                "KEY_REVOKED",
                f"{key_id} was revoked"
            )

            return

    raise ValueError(
        f"{key_id} not found."
    )

# =========================
# Start Application
# =========================

registry = load_registry()

active_key_id = get_active_key(registry)

if not active_key_id:
    st.error("No active key available.")
    st.stop()

try:
    active_key = get_key(active_key_id)
    cipher = Fernet(active_key)

except (FileNotFoundError, ValueError) as error:
    st.error(f"Key error: {error}")
    st.stop()


# =========================
# Sidebar
# =========================

st.title("🔐 SecureVault")

st.caption(
    "Secure Data Encryption & Key Management"
)

page = st.sidebar.radio(
    "Menu",
    [
        "Dashboard",
        "Encryption",
        "Decryption",
        "Key Management",
        "Audit Logs"
    ]
)


# =========================
# Dashboard
# =========================

if page == "Dashboard":

    st.header("Dashboard")

    active_count = sum(
        1 for item in registry
        if item["status"] == "ACTIVE"
    )

    retired_count = sum(
        1 for item in registry
        if item["status"] == "RETIRED"
    )

    revoked_count = sum(
        1 for item in registry
        if item["status"] == "REVOKED"
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Active Keys",
            active_count
        )

    with col2:
        st.metric(
            "Retired Keys",
            retired_count
        )

    with col3:
        st.metric(
            "Revoked Keys",
            revoked_count
        )

    st.divider()

    st.subheader("Current Key")

    st.success(
        f"🔑 {active_key_id} — ACTIVE"
    )

    st.write(
        "SecureVault encrypts data using "
        "Fernet symmetric encryption."
    )

    st.write(
        "Keys can be rotated and revoked "
        "through the Key Management section."
    )


# =========================
# Encryption
# =========================

elif page == "Encryption":

    st.header("🔒 Encrypt Data")

    text = st.text_area(
        "Enter text to encrypt",
        placeholder="Enter sensitive information..."
    )

    if st.button(
        "Encrypt",
        type="primary"
    ):

        if not text.strip():

            st.error(
                "Please enter some text."
            )

        else:

            registry = load_registry()
            active_key_id = get_active_key(
                registry
            )

            try:
                active_key = get_key(
                    active_key_id
                )

                current_cipher = Fernet(
                    active_key
                )

                encrypted = current_cipher.encrypt(
                    text.encode("utf-8")
                ).decode("utf-8")

                result = {
                    "key_id": active_key_id,
                    "data": encrypted
                }

                result_text = json.dumps(
                    result
                )

                st.session_state[
                    "encrypted_data"
                ] = result_text

                audit(
                    "DATA_ENCRYPTED",
                    f"Data encrypted using "
                    f"{active_key_id}"
                )

                st.success(
                    "Data encrypted successfully."
                )

                st.text_area(
                    "Encrypted Data",
                    value=result_text,
                    height=150
                )

                st.caption(
                    "Save this encrypted data "
                    "for decryption."
                )

            except (
                FileNotFoundError,
                ValueError
            ) as error:

                st.error(
                    f"Encryption failed: {error}"
                )


# =========================
# Decryption
# =========================

elif page == "Decryption":

    st.header("🔓 Decrypt Data")

    encrypted_input = st.text_area(
        "Enter encrypted data",
        value=st.session_state.get(
            "encrypted_data",
            ""
        ),
        height=150
    )

    if st.button(
        "Decrypt",
        type="primary"
    ):

        if not encrypted_input.strip():

            st.error(
                "Please enter encrypted data."
            )

        else:

            try:
                package = json.loads(
                    encrypted_input
                )

                key_id = package["key_id"]
                encrypted_data = package["data"]

                registry = load_registry()

                key_info = next(
                    (
                        item
                        for item in registry
                        if item["key_id"] == key_id
                    ),
                    None
                )

                if key_info is None:
                    raise ValueError(
                        "Encryption key not found."
                    )

                if key_info["status"] == "REVOKED":

                    audit(
                        "DECRYPTION_BLOCKED",
                        f"{key_id} is revoked"
                    )

                    st.error(
                        f"Decryption blocked. "
                        f"{key_id} is revoked."
                    )

                else:

                    old_key = get_key(
                        key_id
                    )

                    old_cipher = Fernet(
                        old_key
                    )

                    decrypted = old_cipher.decrypt(
                        encrypted_data.encode("utf-8")
                    ).decode("utf-8")

                    audit(
                        "DATA_DECRYPTED",
                        f"Data decrypted using "
                        f"{key_id}"
                    )

                    st.success(
                        "Data decrypted successfully."
                    )

                    st.text_area(
                        "Decrypted Data",
                        value=decrypted,
                        height=100
                    )

            except (
                InvalidToken,
                KeyError,
                json.JSONDecodeError,
                ValueError,
                FileNotFoundError,
                UnicodeDecodeError
            ):

                audit(
                    "DECRYPTION_FAILED",
                    "Invalid encrypted data or key"
                )

                st.error(
                    "Decryption failed. "
                    "Check the encrypted data."
                )


# =========================
# Key Management
# =========================

elif page == "Key Management":

    st.header("🔑 Key Management")

    registry = load_registry()

    st.subheader("Key Registry")

    for item in registry:

        key_id = item["key_id"]
        status = item["status"]
        created = item["created_at"]

        if status == "ACTIVE":

            st.success(
                f"🔑 {key_id} — {status}"
            )

        elif status == "RETIRED":

            st.warning(
                f"🕘 {key_id} — {status}"
            )

        elif status == "REVOKED":

            st.error(
                f"🚫 {key_id} — {status}"
            )

        st.caption(
            f"Created: {created}"
        )

        st.divider()

    # Rotation
    st.subheader("Rotate Key")

    st.write(
        "Create a new active key and retire "
        "the current active key."
    )

    if st.button(
        "Generate New Key",
        type="primary"
    ):

        try:

            new_id = rotate_key()

            st.success(
                f"{new_id} is now active."
            )

            st.rerun()

        except (
            ValueError,
            OSError
        ) as error:

            st.error(
                f"Rotation failed: {error}"
            )

    # Revocation
    st.subheader("Revoke Key")

    retired_keys = [
        item["key_id"]
        for item in registry
        if item["status"] == "RETIRED"
    ]

    if retired_keys:

        selected_key = st.selectbox(
            "Select retired key",
            retired_keys
        )

        if st.button(
            "Revoke Selected Key"
        ):

            try:

                revoke_key(
                    selected_key
                )

                st.success(
                    f"{selected_key} revoked."
                )

                st.rerun()

            except ValueError as error:

                st.error(
                    str(error)
                )

    else:

        st.info(
            "No retired keys available."
        )


# =========================
# Audit Logs
# =========================

elif page == "Audit Logs":

    st.header("📝 Audit Logs")

    if not LOG_FILE.exists():

        st.info(
            "No activity recorded yet."
        )

    else:

        lines = LOG_FILE.read_text(
            encoding="utf-8"
        ).splitlines()

        if not lines:

            st.info(
                "No activity recorded yet."
            )

        else:

            for line in reversed(
                lines[-50:]
            ):

                try:

                    event = json.loads(line)

                    st.code(
                        f"Time: {event['time']}\n"
                        f"Event: {event['event']}\n"
                        f"Details: {event['details']}"
                    )

                except (
                    json.JSONDecodeError,
                    KeyError
                ):

                    continue


# =========================
# Footer
# =========================

st.divider()

st.caption(
    "SecureVault • Data Encryption & Key Management"
)
