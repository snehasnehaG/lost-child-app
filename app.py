import secrets
import hashlib
import hmac
import re
import sqlite3
import string
from collections.abc import Mapping
from datetime import datetime, timedelta
from io import BytesIO

import qrcode
import streamlit as st

st.set_page_config(page_title="Lost Child Response Board")


def get_secret(key, default=None):
    try:
        return st.secrets.get(key, default)
    except Exception:
        return default

# Use the host computer's LAN address so phones on the same Wi-Fi can open QR links.
# Update this if the computer's local network address changes.
BASE_URL = str(get_secret("APP_BASE_URL", "")).strip()
DB_PATH = "event.db"
ZONES = [
    "Main Gate",
    "Food Court",
    "Stage Area",
    "Restrooms",
    "First Aid",
    "Parking",
    "Kids Zone",
    "Exit Gates",
    "Lost & Found",
]
PHONE_PATTERN = re.compile(r"(?<!\d)\+?\d(?:[\s().-]*\d){6,}(?!\d)")
PHONE_DIGITS = re.compile(r"^\d{10,15}$")


def redact_phone_numbers(value):
    return PHONE_PATTERN.sub("[phone hidden]", str(value or ""))


def public_safe_update(message, alias=None, caregiver=None):
    safe_message = redact_phone_numbers(message)
    for private_name in (alias, caregiver):
        if private_name and len(private_name.strip()) > 1:
            safe_message = re.sub(
                re.escape(private_name.strip()), "[name hidden]", safe_message, flags=re.IGNORECASE
            )
    return safe_message


def init_db():
    """Create the event response database tables if they do not already exist."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS children (
                token TEXT PRIMARY KEY,
                alias TEXT,
                age INTEGER,
                height TEXT,
                descr TEXT,
                caregiver TEXT,
                phone TEXT,
                photo BLOB,
                created_at TEXT,
                consent_at TEXT
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT,
                token TEXT,
                alias TEXT,
                age INTEGER,
                height TEXT,
                descr TEXT,
                last_zone TEXT,
                last_time TEXT,
                caregiver TEXT,
                phone TEXT,
                status TEXT DEFAULT 'OPEN',
                lead TEXT,
                created_at TEXT,
                closed_at TEXT,
                phone_check_salt TEXT,
                phone_check_hash TEXT
            );

            CREATE TABLE IF NOT EXISTS zones (
                incident_id INTEGER,
                zone TEXT,
                status TEXT DEFAULT 'pending',
                assigned_to TEXT,
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS updates (
                incident_id INTEGER,
                message TEXT,
                "by" TEXT,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS found (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT,
                age INTEGER,
                descr TEXT,
                zone TEXT,
                reporter TEXT,
                status TEXT DEFAULT 'OPEN',
                matched_incident INTEGER,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS audit (
                ts TEXT,
                "user" TEXT,
                action TEXT,
                incident_id INTEGER
            );
            CREATE TABLE IF NOT EXISTS login_attempts (username TEXT NOT NULL, ts TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS submission_limits (
                kind TEXT NOT NULL, subject TEXT NOT NULL, ts TEXT NOT NULL
            );
            """
        )
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='help_requests'").fetchone() is None:
            conn.execute("CREATE TABLE help_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER, token TEXT, phone TEXT, details TEXT, created_at TEXT)")
        incident_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(incidents)").fetchall()
        }
        if "phone_check_salt" not in incident_columns:
            conn.execute("ALTER TABLE incidents ADD COLUMN phone_check_salt TEXT")
        if "phone_check_hash" not in incident_columns:
            conn.execute("ALTER TABLE incidents ADD COLUMN phone_check_hash TEXT")
        child_columns = {row[1] for row in conn.execute("PRAGMA table_info(children)")}
        if "consent_at" not in child_columns:
            conn.execute("ALTER TABLE children ADD COLUMN consent_at TEXT")


def phone_verifier(phone, code, salt=None):
    salt = salt or secrets.token_hex(16)
    digits = "".join(character for character in (phone or "") if character.isdigit())
    last_four = digits[-4:]
    digest = hashlib.sha256(f"{salt}:{code}:{last_four}".encode("utf-8")).hexdigest()
    return salt, digest


def run(sql, args=()):
    """Execute a write query and commit it to the event database."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(sql, args)
        conn.commit()
        return cursor.lastrowid


def q(sql, args=()):
    """Execute a read query and return all matching rows."""
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(sql, args).fetchall()


def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def log(action, incident_id=None, user=None):
    if user is None:
        user = st.session_state.get("user", "system")
    run(
        'INSERT INTO audit (ts, "user", action, incident_id) VALUES (?, ?, ?, ?)',
        (now(), user, action, incident_id),
    )


init_db()


def staff_accounts():
    try:
        configured = get_secret("staff", {})
        if not isinstance(configured, Mapping):
            return {}
        valid = {}
        for username, account in configured.items():
            if not isinstance(account, Mapping) or account.get("role") not in ("lead", "staff", "volunteer"):
                continue
            try:
                salt = bytes.fromhex(account.get("salt", ""))
                digest = bytes.fromhex(account.get("hash", ""))
            except (TypeError, ValueError):
                continue
            if salt and len(digest) == hashlib.sha256().digest_size:
                valid[username] = account
        return valid
    except Exception:
        return {}


def verify_staff(username, password):
    accounts = staff_accounts()
    if not accounts:
        return ("lead" if username == "demo" and password == "demo" else None), True
    account = accounts.get(username)
    if not isinstance(account, Mapping) or account.get("role") not in ("lead", "staff", "volunteer"):
        return None, False
    try:
        salt, expected = bytes.fromhex(account["salt"]), bytes.fromhex(account["hash"])
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
        return (account["role"] if hmac.compare_digest(actual, expected) else None), False
    except (KeyError, ValueError, TypeError):
        return None, False


def allow_submission(kind, subject):
    """Enforce session cooldown and persistent per-token/phone hourly limit."""
    subject = str(subject or "anonymous")
    key = f"last_submit_{kind}"
    current = datetime.now().astimezone()
    previous = st.session_state.get(key)
    if previous and current - previous < timedelta(minutes=2):
        return False, "Please wait 2 minutes before submitting again."
    cutoff = (current - timedelta(hours=1)).isoformat(timespec="seconds")
    count = q("SELECT COUNT(*) FROM submission_limits WHERE kind = ? AND subject = ? AND ts >= ?", (kind, subject, cutoff))[0][0]
    if count >= 10:
        return False, "The hourly submission limit has been reached. Please try later."
    run("INSERT INTO submission_limits (kind, subject, ts) VALUES (?, ?, ?)", (kind, subject, current.isoformat(timespec="seconds")))
    st.session_state[key] = current
    return True, ""


def delete_incident_personal_data(conn, incident_id, token):
    if token:
        conn.execute("DELETE FROM children WHERE token = ?", (token,))
    conn.execute("DELETE FROM found WHERE matched_incident = ? OR token = ?", (incident_id, token))
    conn.execute("DELETE FROM help_requests WHERE incident_id = ?", (incident_id,))


def retention_hours_setting():
    try:
        return max(1, int(get_secret("RETENTION_HOURS", 48)))
    except (TypeError, ValueError):
        return 48


def run_retention_cleanup():
    hours = retention_hours_setting()
    cutoff = (datetime.now().astimezone() - timedelta(hours=hours)).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        old = conn.execute("SELECT id, token FROM incidents WHERE created_at < ?", (cutoff,)).fetchall()
        for old_id, token in old:
            delete_incident_personal_data(conn, old_id, token)
            conn.execute("DELETE FROM incidents WHERE id = ?", (old_id,))
            conn.execute("DELETE FROM zones WHERE incident_id = ?", (old_id,))
            conn.execute("DELETE FROM updates WHERE incident_id = ?", (old_id,))
        conn.execute("DELETE FROM children WHERE created_at < ?", (cutoff,))
        conn.execute("DELETE FROM found WHERE created_at < ?", (cutoff,))
        conn.execute("DELETE FROM help_requests WHERE created_at < ?", (cutoff,))
    return len(old)


if not st.session_state.get("retention_cleanup_done"):
    run_retention_cleanup()
    st.session_state.retention_cleanup_done = True


def live_board():
    try:
        from streamlit_autorefresh import st_autorefresh

        st_autorefresh(interval=5000, key="live_board_refresh")
    except ImportError:
        pass

    st.header("Live board")

    help_rows = q("SELECT id, phone, details, created_at FROM help_requests ORDER BY created_at DESC")
    if help_rows:
        st.subheader("Caregiver help requests")
        for request_id, request_phone, details, created_at in help_rows:
            phone_display = "[hidden for volunteers]" if st.session_state.get("role") == "volunteer" else request_phone
            safe_details = redact_phone_numbers(details) if st.session_state.get("role") == "volunteer" else details
            st.info(f"{created_at} · {safe_details or 'No description provided'} · Phone: {phone_display}")

    alerts = q(
        """SELECT id, age, descr, zone, created_at FROM found
           WHERE status = 'OPEN' ORDER BY created_at DESC"""
    )
    for alert_id, age, descr, zone, created_at in alerts:
        if st.session_state.get("role") == "volunteer":
            descr = redact_phone_numbers(descr)
        st.error(
            f"PUBLIC WRISTBAND ALERT · {zone} · age {age if age is not None else 'unknown'} · "
            f"{descr or 'No description provided'} · {created_at}"
        )

    incidents = q(
        "SELECT id, code, alias FROM incidents WHERE status = 'OPEN' ORDER BY created_at DESC"
    )
    if not incidents:
        st.info("There are no open missing-child incidents.")
        return

    incident_ids = [row[0] for row in incidents]
    selected_id = st.selectbox(
        "Open incident",
        incident_ids,
        format_func=lambda incident_id: next(
            f"{code} — {redact_phone_numbers(alias) or 'Child'}"
            for row_id, code, alias in incidents
            if row_id == incident_id
        ),
        key="live_selected_incident",
    )
    selected_rows = q(
        """SELECT code, token, alias, age, height, descr, last_zone, last_time,
                  caregiver, phone
           FROM incidents WHERE id = ?""",
        (selected_id,),
    )
    if not selected_rows:
        st.warning("That incident is no longer available.")
        return

    code, token, alias, age, height, descr, last_zone, last_time, caregiver, phone = selected_rows[0]
    zones = q(
        """SELECT zone, status, assigned_to FROM zones
           WHERE incident_id = ? ORDER BY rowid""",
        (selected_id,),
    )
    cleared_count = sum(1 for _, status, _ in zones if status == "cleared")
    zone_count = len(zones)
    st.write(f"Searching: {cleared_count} of {zone_count} zones cleared")
    st.progress(cleared_count / zone_count if zone_count else 0.0)

    st.subheader("Child details")
    st.write(f"**Incident code:** {code}")
    display_alias = redact_phone_numbers(alias) if st.session_state.get("role") == "volunteer" else alias
    display_height = redact_phone_numbers(height) if st.session_state.get("role") == "volunteer" else height
    display_descr = redact_phone_numbers(descr) if st.session_state.get("role") == "volunteer" else descr
    st.write(f"**Nickname:** {display_alias or 'Not provided'}")
    st.write(f"**Age:** {age if age is not None else 'Not provided'}")
    st.write(f"**Height:** {display_height or 'Not provided'}")
    st.write(f"**Clothing and features:** {display_descr or 'Not provided'}")
    st.write(f"**Last seen:** {last_zone or 'Unknown'} · {last_time or 'Time not provided'}")
    display_caregiver = redact_phone_numbers(caregiver) if st.session_state.get("role") == "volunteer" else caregiver
    st.write(f"**Caregiver:** {display_caregiver or 'Not provided'}")
    if st.session_state.get("role") != "volunteer":
        st.write(f"**Caregiver phone:** {phone or 'Not provided'}")

    st.subheader("Zone search")
    staff_users = [username for username, account in staff_accounts().items() if account.get("role") == "staff"]
    for index, (zone_name, status, assigned_to) in enumerate(zones):
        label = f"**{zone_name}** — {status}"
        if assigned_to:
            label += f" · assigned to {assigned_to}"
        st.write(label)

        if st.session_state.get("role") == "lead" and staff_users:
            with st.form(f"assign_zone_{selected_id}_{index}"):
                assignee = st.selectbox(
                    f"Assign {zone_name}",
                    staff_users,
                    index=staff_users.index(assigned_to) if assigned_to in staff_users else 0,
                    key=f"assign_user_{selected_id}_{index}",
                )
                assign_submitted = st.form_submit_button("Assign zone")
            if assign_submitted:
                run(
                    """UPDATE zones SET status = 'assigned', assigned_to = ?, updated_at = ?
                       WHERE incident_id = ? AND zone = ?""",
                    (assignee, now(), selected_id, zone_name),
                )
                log(f"zone_assigned:{zone_name}:{assignee}", selected_id)
                st.rerun()

        if status != "cleared" and st.session_state.get("role") in ("lead", "staff"):
            if st.button("Mark cleared", key=f"clear_zone_{selected_id}_{index}"):
                run(
                    """UPDATE zones SET status = 'cleared', updated_at = ?
                       WHERE incident_id = ? AND zone = ?""",
                    (now(), selected_id, zone_name),
                )
                log(f"zone_cleared:{zone_name}", selected_id)
                st.rerun()

    st.subheader("Status updates")
    update_submitted = False
    message = ""
    if st.session_state.get("role") in ("lead", "staff"):
        with st.form(f"post_update_{selected_id}", clear_on_submit=True):
            message = st.text_area(
                "Approved status update", max_chars=500, key=f"update_message_{selected_id}"
            )
            update_submitted = st.form_submit_button("Post update")
    if update_submitted:
        incident_alias, incident_caregiver, incident_phone = q(
            "SELECT alias, caregiver, phone FROM incidents WHERE id = ?", (selected_id,)
        )[0]
        incident_phone_digits = "".join(c for c in (incident_phone or "") if c.isdigit())
        message_digits = "".join(c for c in message if c.isdigit())
        has_private_name = any(
            value and value.strip().casefold() in message.casefold()
            for value in (incident_alias, incident_caregiver)
        )
        if not message.strip():
            st.warning("Enter an update before posting.")
        elif PHONE_PATTERN.search(message) or (
            incident_phone_digits and incident_phone_digits in message_digits
        ) or has_private_name:
            st.error("Status updates cannot include a phone number or the child's or caregiver's name.")
        elif len(message.strip()) > 500:
            st.error("Keep status updates under 500 characters.")
        else:
            run(
                'INSERT INTO updates (incident_id, message, "by", created_at) VALUES (?, ?, ?, ?)',
                (selected_id, message.strip(), st.session_state.get("user", "system"), now()),
            )
            log("incident_update_posted", selected_id)
            st.rerun()

    updates = q(
        'SELECT message, "by", created_at FROM updates WHERE incident_id = ? ORDER BY created_at DESC',
        (selected_id,),
    )
    if st.session_state.get("role") == "volunteer":
        st.caption("Status updates are available to lead and staff accounts.")
    else:
        for update_message, update_by, update_at in updates:
            st.write(f"{update_at} · {update_by}: {update_message}")


def report_missing():
    if st.session_state.get("role") not in ("lead", "staff"):
        st.warning("This page is available to lead and staff accounts only.")
        return

    st.header("Report missing")
    wristband_tab, manual_tab = st.tabs(["From registered wristband", "Manual entry"])

    with wristband_tab:
        with st.form("report_missing_wristband_form"):
            token = st.text_input("Wristband ID", max_chars=8).strip().upper()
            last_zone = st.selectbox("Last seen zone", ZONES, key="wristband_last_zone")
            last_date = st.date_input("Last seen date", key="wristband_last_date")
            last_clock = st.time_input("Last seen time", key="wristband_last_clock")
            wristband_submitted = st.form_submit_button("Create incident from wristband")

        if wristband_submitted:
            st.session_state.pop("report_incident_result", None)
            if not re.fullmatch(r"[A-Z0-9]{8}", token):
                st.error("Enter an 8-character wristband ID using letters and numbers.")
            else:
                child_rows = q(
                    """SELECT token, alias, age, height, descr, caregiver, phone
                       FROM children WHERE token = ?""",
                    (token,),
                )
                if not child_rows:
                    st.error("No registered child was found for that wristband ID.")
                else:
                    child = child_rows[0]
                    incident_id, code = create_incident(
                        token=child[0],
                        alias=child[1],
                        age=child[2],
                        height=child[3],
                        descr=child[4],
                        caregiver=child[5],
                        phone=child[6],
                        last_zone=last_zone,
                        last_time=datetime.combine(last_date, last_clock).astimezone().isoformat(
                            timespec="minutes"
                        ),
                    )
                    st.session_state.report_incident_result = (incident_id, code)

    with manual_tab:
        with st.form("report_missing_manual_form"):
            alias = st.text_input("Child nickname", key="manual_alias")
            age = st.number_input("Age", min_value=0, max_value=18, step=1, key="manual_age")
            height = st.text_input("Height", key="manual_height")
            descr = st.text_area("Clothing and identifying features", key="manual_descr")
            caregiver = st.text_input("Caregiver name", key="manual_caregiver")
            phone = st.text_input("Caregiver phone", key="manual_phone")
            manual_zone = st.selectbox("Last seen zone", ZONES, key="manual_last_zone")
            manual_date = st.date_input("Last seen date", key="manual_last_date")
            manual_clock = st.time_input("Last seen time", key="manual_last_clock")
            manual_submitted = st.form_submit_button("Create incident")

        if manual_submitted:
            st.session_state.pop("report_incident_result", None)
            phone_digits = "".join(character for character in phone if character.isdigit())
            if not alias.strip() or not caregiver.strip() or not PHONE_DIGITS.fullmatch(phone.strip()):
                st.error("Enter the child nickname, caregiver name, and a phone number with 10 to 15 digits.")
            else:
                incident_id, code = create_incident(
                    token=None,
                    alias=alias.strip(),
                    age=int(age),
                    height=height.strip(),
                    descr=descr.strip(),
                    caregiver=caregiver.strip(),
                    phone=phone.strip(),
                    last_zone=manual_zone,
                    last_time=datetime.combine(manual_date, manual_clock).astimezone().isoformat(
                        timespec="minutes"
                    ),
                )
                st.session_state.report_incident_result = (incident_id, code)

    result = st.session_state.get("report_incident_result")
    if result:
        incident_id, code = result
        st.success(f"Incident opened. Give this code to the caregiver: **{code}**")


def create_incident(token, alias, age, height, descr, caregiver, phone, last_zone, last_time):
    while True:
        code = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(5))
        if not q("SELECT 1 FROM incidents WHERE code = ?", (code,)):
            break

    created_at = now()
    lead = st.session_state.get("user") if st.session_state.get("role") == "lead" else None
    phone_salt, phone_hash = phone_verifier(phone, code)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """INSERT INTO incidents
               (code, token, alias, age, height, descr, last_zone, last_time,
                caregiver, phone, status, lead, created_at, phone_check_salt, phone_check_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?)""",
            (
                code,
                token,
                alias,
                age,
                height,
                descr,
                last_zone,
                last_time,
                caregiver,
                phone,
                lead,
                created_at,
                phone_salt,
                phone_hash,
            ),
        )
        incident_id = cursor.lastrowid
        conn.executemany(
            """INSERT INTO zones (incident_id, zone, status, assigned_to, updated_at)
               VALUES (?, ?, 'pending', NULL, ?)""",
            [(incident_id, zone, created_at) for zone in ZONES],
        )
        conn.execute(
            'INSERT INTO updates (incident_id, message, "by", created_at) VALUES (?, ?, ?, ?)',
            (
                incident_id,
                "Incident opened. Search team is being assigned.",
                st.session_state.get("user", "system"),
                created_at,
            ),
        )

    log("incident_opened", incident_id)
    run("UPDATE help_requests SET incident_id = ? WHERE phone = ? AND incident_id IS NULL", (incident_id, phone))
    return incident_id, code


def found_a_child():
    st.header("Found a child")
    with st.form("found_child_form", clear_on_submit=True):
        age = st.number_input("Approximate age", min_value=0, max_value=18, step=1)
        descr = st.text_area("Clothing and identifying features")
        zone = st.selectbox("Zone found", ZONES)
        token = st.text_input("Wristband ID (optional)").strip().upper()
        submitted = st.form_submit_button("Find possible matches")

    if submitted:
        if not descr.strip():
            st.session_state.pop("found_search", None)
            st.error("Add a short description of the child's clothing or features.")
            return
        if token and not re.fullmatch(r"[A-Z0-9]{8}", token):
            st.session_state.pop("found_search", None)
            st.error("Wristband IDs are 8 letters or numbers. Check the ID and try again.")
            return
        st.session_state.found_search = {
            "age": int(age),
            "descr": descr.strip(),
            "zone": zone,
            "token": token or None,
            "linked_incident": None,
        }
        log("found_child_reported")

    search = st.session_state.get("found_search")
    if not search:
        return

    incidents = q(
        """SELECT id, code, alias, age, descr, last_zone FROM incidents
           WHERE status = 'OPEN'"""
    )
    found_words = {
        word.casefold()
        for word in re.findall(r"\b[^\W\d_]+\b", search["descr"], flags=re.UNICODE)
        if len(word) > 3
    }
    ranked = []
    for incident_id, code, alias, incident_age, incident_descr, last_zone in incidents:
        score = 0
        if incident_age is not None and abs(int(incident_age) - search["age"]) <= 2:
            score += 2
        incident_words = {
            word.casefold()
            for word in re.findall(r"\b[^\W\d_]+\b", incident_descr or "", flags=re.UNICODE)
            if len(word) > 3
        }
        score += len(found_words & incident_words)
        if (last_zone or "").casefold() == search["zone"].casefold():
            score += 1
        ranked.append((score, incident_id, code, alias, incident_age, incident_descr, last_zone))

    ranked.sort(key=lambda match: (-match[0], match[2] or ""))
    st.subheader("Possible incident matches")
    if not ranked:
        st.info("There are no open incidents to match.")
        return

    linked_incident = search.get("linked_incident")
    for score, incident_id, code, alias, incident_age, incident_descr, last_zone in ranked:
        with st.container(border=True):
            st.write(f"**{code}** · match score {score}")
            volunteer = st.session_state.get("role") == "volunteer"
            display_alias = redact_phone_numbers(alias) if volunteer else alias
            display_descr = redact_phone_numbers(incident_descr) if volunteer else incident_descr
            st.write(f"Nickname: {display_alias or 'Not provided'} · age {incident_age if incident_age is not None else 'unknown'}")
            st.write(f"Last seen: {last_zone or 'Unknown'} · {display_descr or 'No description'}")
            if linked_incident == incident_id:
                st.success("This found report is linked to this incident for verification.")
            elif linked_incident is None:
                if st.button("Link to this incident", key=f"link_found_{incident_id}"):
                    run(
                        """INSERT INTO found
                           (token, age, descr, zone, reporter, status, matched_incident, created_at)
                           VALUES (?, ?, ?, ?, ?, 'MATCHED', ?, ?)""",
                        (
                            search["token"],
                            search["age"],
                            search["descr"],
                            search["zone"],
                            st.session_state.get("user", "system"),
                            incident_id,
                            now(),
                        ),
                    )
                    run(
                        'INSERT INTO updates (incident_id, message, "by", created_at) VALUES (?, ?, ?, ?)',
                        (
                            incident_id,
                            "A child who may match has been found. Staff are verifying.",
                            st.session_state.get("user", "system"),
                            now(),
                        ),
                    )
                    log("found_report_linked", incident_id)
                    search["linked_incident"] = incident_id
                    st.session_state.found_search = search
                    st.rerun()


def wristband_lookup():
    st.header("Wristband lookup")
    with st.form("wristband_lookup_form"):
        token = st.text_input("Wristband ID", max_chars=8).strip().upper()
        submitted = st.form_submit_button("Look up child")

    if submitted:
        log("wristband_lookup")
        st.session_state.wristband_lookup_token = token
        st.session_state.wristband_lookup_performed = True
        if not re.fullmatch(r"[A-Z0-9]{8}", token):
            st.session_state.wristband_lookup_invalid = True
        else:
            st.session_state.wristband_lookup_invalid = False

    if not st.session_state.get("wristband_lookup_performed"):
        return

    lookup_token = st.session_state.get("wristband_lookup_token", "")
    if st.session_state.get("wristband_lookup_invalid"):
        st.error("Enter an 8-character wristband ID using letters and numbers.")
        return
    child = q(
        """SELECT token, alias, age, height, descr, caregiver, phone, photo
           FROM children WHERE token = ?""",
        (lookup_token,),
    )
    if not child:
        st.error("No registered child was found for that wristband ID.")
        return

    token, alias, age, height, descr, caregiver, phone, photo = child[0]
    st.write(f"**Wristband ID:** {token}")
    st.write(f"**Nickname:** {redact_phone_numbers(alias) or 'Not provided'}")
    st.write(f"**Age:** {age if age is not None else 'Not provided'}")
    st.write(f"**Height:** {redact_phone_numbers(height) or 'Not provided'}")
    st.write(f"**Clothing and identifying features:** {redact_phone_numbers(descr) or 'Not provided'}")
    st.write(f"**Caregiver:** {redact_phone_numbers(caregiver) or 'Not provided'}")
    if st.session_state.get("role") != "volunteer":
        st.write(f"**Caregiver phone:** {phone or 'Not provided'}")
        if photo:
            st.image(photo, caption="Registered child photo")


def reunify():
    if st.session_state.get("role") not in ("lead", "staff"):
        st.warning("This page is available to lead and staff accounts only.")
        return

    st.header("Reunify")
    incidents = q(
        "SELECT id, code, alias FROM incidents WHERE status = 'OPEN' ORDER BY created_at DESC"
    )
    if not incidents:
        st.info("There are no open incidents to reunify.")
        return

    with st.form("reunify_form"):
        incident_id = st.selectbox(
            "Incident",
            [row[0] for row in incidents],
            format_func=lambda selected: next(
                f"{code} — {alias or 'Child'}"
                for row_id, code, alias in incidents
                if row_id == selected
            ),
        )
        where_found = st.text_input("Where found")
        described = st.checkbox("Caregiver described child correctly before seeing them")
        verified = st.checkbox("ID/phone verified")
        two_staff = st.checkbox("Two staff present")
        confirmed = st.form_submit_button("Confirm reunification")

    if confirmed:
        if not all((described, verified, two_staff)):
            st.error("Complete all three safety checks before confirming reunification.")
        elif not where_found.strip():
            st.error("Enter where the child was found.")
        else:
            incident_rows = q(
                "SELECT code, phone, phone_check_salt FROM incidents WHERE id = ? AND status = 'OPEN'",
                (incident_id,),
            )
            if not incident_rows:
                st.error("That incident is no longer open.")
                return
            code, phone, phone_salt = incident_rows[0]
            incident_token = q("SELECT token FROM incidents WHERE id = ?", (incident_id,))[0][0]
            if phone:
                phone_salt, phone_hash = phone_verifier(phone, code, phone_salt)
            else:
                phone_hash = None
            closed_at = now()
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    """UPDATE incidents SET status = 'CLOSED', phone = NULL,
                       closed_at = ?, phone_check_salt = ?, phone_check_hash = ? WHERE id = ?""",
                    (closed_at, phone_salt, phone_hash, incident_id),
                )
                conn.execute(
                    "UPDATE found SET status = 'CLOSED' WHERE matched_incident = ?",
                    (incident_id,),
                )
                conn.execute(
                    'INSERT INTO updates (incident_id, message, "by", created_at) VALUES (?, ?, ?, ?)',
                    (
                        incident_id,
                        "Child found and reunified. Search stood down.",
                        st.session_state.get("user", "system"),
                        closed_at,
                    ),
                )
                delete_incident_personal_data(conn, incident_id, incident_token)
                conn.execute(
                    'INSERT INTO updates (incident_id, message, "by", created_at) VALUES (?, ?, ?, ?)',
                    (
                        incident_id,
                        f"Child found at: {where_found.strip()}.",
                        st.session_state.get("user", "system"),
                        closed_at,
                    ),
                )
            log(f"incident_reunified:found_at:{where_found.strip()}", incident_id)
            st.error("STAND DOWN — Child found and reunified. Search stood down.")


CAREGIVER_TEXT = {
    "English": {
        "title": "Caregiver status",
        "language": "Language",
        "code": "Incident code",
        "last4": "Last 4 digits of caregiver phone",
        "submit": "Check status",
        "hint": "Enter your incident code and the last four digits of your phone number.",
        "not_found": "No matching incident was found. Check the code and phone digits.",
        "invalid": "Enter a 5-character incident code and 4 numeric phone digits.",
        "status": "Status",
        "open": "OPEN",
        "closed": "CLOSED",
        "searching": "Searching: {cleared} of {total} zones cleared",
        "updates": "Last 5 updates",
        "no_updates": "There are no updates yet.",
        "found": "Your child has been found. Please go to the staff desk.",
        "update_open": "Incident opened. Search team is being assigned.",
        "update_match": "A child who may match has been found. Staff are verifying.",
        "update_closed": "Child found and reunified. Search stood down.",
        "update_location": "Child found at: {location}.",
    },
    "Hindi": {
        "title": "अभिभावक स्थिति",
        "language": "भाषा",
        "code": "घटना कोड",
        "last4": "अभिभावक के फोन के आखिरी 4 अंक",
        "submit": "स्थिति देखें",
        "hint": "अपना घटना कोड और फोन नंबर के आखिरी चार अंक दर्ज करें।",
        "not_found": "कोई मेल खाती घटना नहीं मिली। कोड और फोन के अंक जाँचें।",
        "invalid": "5 अक्षरों या अंकों का घटना कोड और फोन के 4 अंक दर्ज करें।",
        "status": "स्थिति",
        "open": "खुला",
        "closed": "बंद",
        "searching": "खोज जारी: {total} में से {cleared} ज़ोन साफ़ हुए",
        "updates": "पिछले 5 अपडेट",
        "no_updates": "अभी कोई अपडेट नहीं है।",
        "found": "आपका बच्चा मिल गया है। कृपया स्टाफ डेस्क पर जाएँ।",
        "update_open": "घटना दर्ज की गई है। खोज दल को तैनात किया जा रहा है।",
        "update_match": "संभवतः मेल खाने वाला बच्चा मिला है। स्टाफ पुष्टि कर रहा है।",
        "update_closed": "बच्चा मिल गया और परिवार से मिल गया। खोज रोक दी गई है।",
        "update_location": "बच्चा यहाँ मिला: {location}।",
    },
    "Kannada": {
        "title": "ಪೋಷಕರ ಸ್ಥಿತಿ",
        "language": "ಭಾಷೆ",
        "code": "ಘಟನೆ ಕೋಡ್",
        "last4": "ಪೋಷಕರ ಫೋನ್‌ನ ಕೊನೆಯ 4 ಅಂಕೆಗಳು",
        "submit": "ಸ್ಥಿತಿ ಪರಿಶೀಲಿಸಿ",
        "hint": "ನಿಮ್ಮ ಘಟನೆ ಕೋಡ್ ಮತ್ತು ಫೋನ್ ಸಂಖ್ಯೆಯ ಕೊನೆಯ ನಾಲ್ಕು ಅಂಕೆಗಳನ್ನು ನಮೂದಿಸಿ.",
        "not_found": "ಹೊಂದಾಣಿಕೆಯ ಘಟನೆ ಕಂಡುಬಂದಿಲ್ಲ. ಕೋಡ್ ಮತ್ತು ಫೋನ್ ಅಂಕೆಗಳನ್ನು ಪರಿಶೀಲಿಸಿ.",
        "invalid": "5 ಅಕ್ಷರ/ಅಂಕೆಗಳ ಘಟನೆ ಕೋಡ್ ಮತ್ತು ಫೋನ್‌ನ 4 ಅಂಕೆಗಳನ್ನು ನಮೂದಿಸಿ.",
        "status": "ಸ್ಥಿತಿ",
        "open": "ತೆರೆದಿದೆ",
        "closed": "ಮುಚ್ಚಲಾಗಿದೆ",
        "searching": "ಹುಡುಕಾಟ: {total} ವಲಯಗಳಲ್ಲಿ {cleared} ವಲಯಗಳು ಪರಿಶೀಲಿಸಲಾಗಿದೆ",
        "updates": "ಕೊನೆಯ 5 ನವೀಕರಣಗಳು",
        "no_updates": "ಇನ್ನೂ ಯಾವುದೇ ನವೀಕರಣಗಳಿಲ್ಲ.",
        "found": "ನಿಮ್ಮ ಮಗು ಪತ್ತೆಯಾಗಿದೆ. ದಯವಿಟ್ಟು ಸಿಬ್ಬಂದಿ ಡೆಸ್ಕ್‌ಗೆ ಹೋಗಿ.",
        "update_open": "ಘಟನೆ ದಾಖಲಿಸಲಾಗಿದೆ. ಹುಡುಕಾಟ ತಂಡವನ್ನು ನಿಯೋಜಿಸಲಾಗುತ್ತಿದೆ.",
        "update_match": "ಹೊಂದಿಕೆಯಾಗಬಹುದಾದ ಮಗು ಪತ್ತೆಯಾಗಿದೆ. ಸಿಬ್ಬಂದಿ ಪರಿಶೀಲಿಸುತ್ತಿದ್ದಾರೆ.",
        "update_closed": "ಮಗು ಪತ್ತೆಯಾಗಿ ಕುಟುಂಬದೊಂದಿಗೆ ಸೇರಿಸಲಾಗಿದೆ. ಹುಡುಕಾಟ ನಿಲ್ಲಿಸಲಾಗಿದೆ.",
        "update_location": "ಮಗು ಇಲ್ಲಿ ಪತ್ತೆಯಾಗಿದೆ: {location}.",
    },
}


def caregiver_page():
    prior_language = st.session_state.get("caregiver_language", "English")
    language = st.selectbox(
        CAREGIVER_TEXT[prior_language]["language"],
        list(CAREGIVER_TEXT),
        key="caregiver_language",
    )
    text = CAREGIVER_TEXT[language]
    st.title(text["title"])
    st.write(text["hint"])
    with st.form("caregiver_status_form"):
        code = st.text_input(text["code"], max_chars=5).strip().upper()
        last4 = st.text_input(text["last4"], max_chars=4, type="password").strip()
        submitted = st.form_submit_button(text["submit"])

    if submitted:
        if not re.fullmatch(r"[A-Z0-9]{5}", code) or not re.fullmatch(r"\d{4}", last4):
            st.session_state.caregiver_status_lookup_done = False
            st.session_state.caregiver_status_lookup_error = "invalid"
            st.session_state.caregiver_status_lookup_logged = True
            log("caregiver_status_lookup_invalid", user="caregiver")
        else:
            st.session_state.caregiver_status_lookup = (code, last4)
            st.session_state.caregiver_status_lookup_done = True
            st.session_state.caregiver_status_lookup_error = None
            st.session_state.caregiver_status_lookup_logged = False

    error_key = st.session_state.get("caregiver_status_lookup_error")
    if error_key:
        st.error(text[error_key])

    if not st.session_state.get("caregiver_status_lookup_done"):
        return

    code, last4 = st.session_state.caregiver_status_lookup
    rows = q(
        """SELECT id, code, status, phone, phone_check_salt, phone_check_hash,
                  alias, caregiver
           FROM incidents WHERE code = ?""",
        (code,),
    )
    matched = None
    if len(last4) == 4 and last4.isdigit():
        for row in rows:
            incident_id, incident_code, status, phone, salt, saved_hash, alias, caregiver = row
            if saved_hash and salt:
                candidate_hash = phone_verifier(last4, incident_code, salt)[1]
                is_valid = hmac.compare_digest(candidate_hash, saved_hash)
            else:
                digits = "".join(character for character in (phone or "") if character.isdigit())
                is_valid = bool(digits) and hmac.compare_digest(digits[-4:], last4)
            if is_valid:
                matched = (incident_id, incident_code, status, alias, caregiver)
                break

    if not matched:
        if not st.session_state.get("caregiver_status_lookup_logged"):
            log("caregiver_status_lookup_failed", user="caregiver")
            st.session_state.caregiver_status_lookup_logged = True
        st.error(text["not_found"])
        return

    incident_id, incident_code, status, alias, caregiver = matched
    if not st.session_state.get("caregiver_status_lookup_logged"):
        log("caregiver_status_lookup", incident_id, user="caregiver")
        st.session_state.caregiver_status_lookup_logged = True
    zones = q("SELECT status FROM zones WHERE incident_id = ?", (incident_id,))
    cleared = sum(1 for (zone_status,) in zones if zone_status == "cleared")
    status_text = text["closed"] if status == "CLOSED" else text["open"]
    st.write(f"**{text['status']}:** {status_text}")
    st.write(text["searching"].format(cleared=cleared, total=len(zones)))
    if status == "CLOSED":
        st.success(text["found"])

    st.subheader(text["updates"])
    updates = q(
        'SELECT message, created_at FROM updates WHERE incident_id = ? ORDER BY created_at DESC LIMIT 5',
        (incident_id,),
    )
    if not updates:
        st.write(text["no_updates"])
    for message, created_at in updates:
        if message == "Incident opened. Search team is being assigned.":
            safe_message = text["update_open"]
        elif message == "A child who may match has been found. Staff are verifying.":
            safe_message = text["update_match"]
        elif message == "Child found and reunified. Search stood down.":
            safe_message = text["update_closed"]
        elif message.startswith("Child found at: "):
            location = message[len("Child found at: ") :].rstrip(".")
            safe_location = public_safe_update(location, alias, caregiver)
            safe_message = text["update_location"].format(location=safe_location)
        else:
            safe_message = public_safe_update(message, alias, caregiver)
        st.write(f"{created_at} · {safe_message}")


def audit_privacy():
    if st.session_state.get("role") != "lead":
        st.warning("This page is available to the lead only.")
        return

    st.header("Audit & privacy")
    if not BASE_URL.startswith("https://"):
        st.warning("APP_BASE_URL is missing or does not use HTTPS. Configure it before public deployment.")
    audit_rows = q('SELECT ts, "user", action, incident_id FROM audit ORDER BY ts DESC')
    st.table(
        [
            {"Time": ts, "User": user, "Action": action, "Incident ID": incident_id}
            for ts, user, action, incident_id in audit_rows
        ]
    )

    st.subheader("Delete all personal data")
    with st.form("privacy_wipe_form"):
        confirmed = st.checkbox("I confirm: permanently delete all personal data.")
        wipe_submitted = st.form_submit_button("Delete all personal data")
    if wipe_submitted:
        if not confirmed:
            st.error("Confirm the privacy wipe before continuing.")
        else:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("DELETE FROM children")
                conn.execute("DELETE FROM found")
                conn.execute("DELETE FROM help_requests")
                conn.execute("DELETE FROM incidents")
                conn.execute("DELETE FROM zones")
                conn.execute("DELETE FROM updates")
                conn.execute("DELETE FROM submission_limits")
            log("privacy_wipe_completed")
            st.success("All personal data was deleted. Audit history was retained.")

    try:
        retention_hours = retention_hours_setting()
    except (TypeError, ValueError):
        retention_hours = 48
    if st.button(f"Run automatic cleanup (older than {retention_hours} hours)"):
        cutoff = (datetime.now().astimezone() - timedelta(hours=retention_hours)).isoformat(timespec="seconds")
        with sqlite3.connect(DB_PATH) as conn:
            old = conn.execute("SELECT id, token FROM incidents WHERE created_at < ?", (cutoff,)).fetchall()
            for old_id, token in old:
                delete_incident_personal_data(conn, old_id, token)
                conn.execute("DELETE FROM incidents WHERE id = ?", (old_id,))
                conn.execute("DELETE FROM zones WHERE incident_id = ?", (old_id,))
                conn.execute("DELETE FROM updates WHERE incident_id = ?", (old_id,))
            conn.execute("DELETE FROM children WHERE created_at < ?", (cutoff,))
            conn.execute("DELETE FROM found WHERE created_at < ?", (cutoff,))
            conn.execute("DELETE FROM help_requests WHERE created_at < ?", (cutoff,))
        log("retention_cleanup_completed")
        st.success("Old closed incidents and related personal data were deleted.")


def register_child():
    if st.session_state.get("role") == "volunteer":
        st.warning("Child registration is available to lead and staff accounts only.")
        return

    st.header("Register child")
    st.write("Create a private wristband QR code for a child and caregiver.")

    with st.form("register_child_form", clear_on_submit=True):
        alias = st.text_input("Child nickname")
        age = st.number_input("Age", min_value=0, max_value=18, step=1)
        height = st.text_input("Height")
        descr = st.text_area("Clothing and identifying features")
        caregiver = st.text_input("Caregiver name")
        phone = st.text_input("Caregiver phone")
        photo_file = st.file_uploader("Optional child photo", type=["png", "jpg", "jpeg"])
        consent = st.checkbox("I agree this information is used only to reunite my child with me during this event and will be deleted afterwards.")
        submitted = st.form_submit_button("Register child")

    if submitted:
        st.session_state.pop("registration_result", None)
        phone_digits = "".join(character for character in phone if character.isdigit())
        if not alias.strip() or not caregiver.strip() or not PHONE_DIGITS.fullmatch(phone.strip()):
            st.error("Enter the child nickname, caregiver name, and a phone number with 10 to 15 digits.")
        elif not consent:
            st.error("Consent is required to register a child.")
        else:
            photo = photo_file.getvalue() if photo_file is not None else None
            while True:
                token = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
                if not q("SELECT 1 FROM children WHERE token = ?", (token,)):
                    break

            run(
                """INSERT INTO children
                   (token, alias, age, height, descr, caregiver, phone, photo, created_at, consent_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    token,
                    alias.strip(),
                    int(age),
                    height.strip(),
                    descr.strip(),
                    caregiver.strip(),
                    phone.strip(),
                    photo,
                    now(),
                    now(),
                ),
            )
            log("child_registered")

            qr_url = f"{BASE_URL.rstrip('/')}/?w={token}"
            qr_image = qrcode.make(qr_url)
            qr_buffer = BytesIO()
            qr_image.save(qr_buffer, format="PNG")
            st.session_state.registration_result = (token, qr_buffer.getvalue())

    result = st.session_state.get("registration_result")
    if result:
        # Rebuild the QR using the current configured base URL, including after a URL change.
        token = result[0] if isinstance(result, tuple) else result
        qr_image = qrcode.make(f"{BASE_URL.rstrip('/')}/?w={token}")
        qr_buffer = BytesIO()
        qr_image.save(qr_buffer, format="PNG")
        qr_png = qr_buffer.getvalue()
        st.success("Registration saved. Keep this QR code with the caregiver.")
        st.caption(f"Wristband ID: {token}")
        st.image(qr_png, caption="Private child wristband QR code", width=240)
        st.download_button(
            "Download QR PNG",
            data=qr_png,
            file_name=f"child-{token}.png",
            mime="image/png",
        )


def privacy_notice():
    st.header("Privacy notice")
    st.write("We collect a child nickname, age, height, clothing and identifying features, caregiver name and phone number, and an optional photo. A wristband token and event search updates are also stored.")
    st.write("Lead and staff accounts can access registered details. Volunteers do not see caregiver phone numbers or photos. Public pages show only the minimum information needed to alert staff and never display names, phone numbers, or photos.")
    st.write("When staff confirm reunification, the linked child registration (including its photo) and related help requests are deleted. Other records are automatically eligible for deletion after the configured retention period (48 hours by default); a lead can also delete all personal data from Audit & privacy.")


def cant_find_child():
    st.header("I can't find my child")
    st.write("Send an alert to event staff. For immediate help, go to the nearest event staff desk.")
    with st.form("cant_find_child_form", clear_on_submit=True):
        phone = st.text_input("Caregiver phone")
        details = st.text_area("Child nickname and brief description")
        submitted = st.form_submit_button("Alert event staff")
    if submitted:
        digits = "".join(c for c in phone if c.isdigit())
        if not PHONE_DIGITS.fullmatch(phone.strip()):
            st.error("Enter a phone number with 10 to 15 digits.")
            return
        allowed, message = allow_submission("cant_find", digits)
        if not allowed:
            st.warning(message)
            return
        run("INSERT INTO help_requests (phone, details, created_at) VALUES (?, ?, ?)", (phone.strip(), details.strip(), now()))
        log("public_cant_find_child", user="public")
        st.success("Event staff have been alerted. Please stay near the staff desk.")


public_token = st.query_params.get("w")
if public_token:
    st.title("Lost Child Response Board")
    st.write("This child may be separated from family. Please stay with the child")
    child = q("SELECT age, descr FROM children WHERE token = ?", (public_token,))
    if not child:
        st.error("Unknown child token. Please alert event staff directly.")
    else:
        age, descr = child[0]
        zone = st.selectbox("Where are you with the child?", ZONES)
        if st.button("Alert staff"):
            allowed, message = allow_submission("qr_alert", public_token)
            if not allowed:
                st.warning(message)
                st.stop()
            run(
                """INSERT INTO found
                   (token, age, descr, zone, reporter, status, matched_incident, created_at)
                   VALUES (?, ?, ?, ?, ?, 'OPEN', NULL, ?)""",
                (public_token, age, descr, zone, "QR alert", now()),
            )
            log("public_child_alert", user="public")
            st.success("Staff have been alerted. Please stay with the child.")
    st.stop()

st.sidebar.title("Lost Child Response Board")
st.sidebar.write("Event staff tools")

if "user" not in st.session_state:
    st.session_state.user = None
    st.session_state.role = None

if st.session_state.user is None:
    public_page = st.sidebar.radio(
        "Public page", ["Staff login", "Register child", "Caregiver", "I can't find my child", "Privacy notice"]
    )
    if public_page == "Register child":
        register_child()
    elif public_page == "Caregiver":
        caregiver_page()
    elif public_page == "I can't find my child":
        cant_find_child()
    elif public_page == "Privacy notice":
        privacy_notice()
    else:
        accounts = staff_accounts()
        if not accounts:
            st.sidebar.warning("No staff secrets are configured. Demo account is DEMO ONLY (username: demo, password: demo).")
        with st.sidebar.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Log in")

        if submitted:
            username = username.strip()
            cutoff = (datetime.now().astimezone() - timedelta(minutes=5)).isoformat(timespec="seconds")
            latest_attempt = q("SELECT MAX(ts) FROM login_attempts WHERE username = ?", (username,))[0][0]
            if latest_attempt and latest_attempt >= cutoff:
                # A sixth request is blocked for five minutes after the fifth failure.
                failures_since_window = q("SELECT COUNT(*) FROM login_attempts WHERE username = ? AND ts >= ?", (username, cutoff))[0][0]
            else:
                failures_since_window = 0
            if failures_since_window >= 5:
                st.sidebar.error("Login temporarily locked. Try again in 5 minutes.")
            else:
                role, demo = verify_staff(username, password)
                if role:
                    st.session_state.user = username
                    st.session_state.role = role
                    if demo:
                        st.session_state.demo_login = True
                    run("DELETE FROM login_attempts WHERE username = ?", (username,))
                    log("login")
                    st.rerun()
                else:
                    run("INSERT INTO login_attempts (username, ts) VALUES (?, ?)", (username, now()))
                    log("login_failed", user=username or "unknown")
                    st.sidebar.error("Invalid username or password.")

        st.title("Lost Child Response Board")
        st.write("Welcome. Please log in to access the event staff board.")
else:
    st.sidebar.write(f"Signed in as **{st.session_state.user}**")
    st.sidebar.write(f"Role: {st.session_state.role}")

    if st.sidebar.button("Log out"):
        log("logout")
        st.session_state.user = None
        st.session_state.role = None
        st.rerun()

    pages = [
        "Live board",
        "Report missing",
        "Found a child",
        "Reunify",
        "Wristband lookup",
    ]
    if st.session_state.role != "volunteer":
        pages.extend(["Caregiver", "Register child"])
    if st.session_state.role == "lead":
        pages.append("Audit & privacy")

    page = st.sidebar.radio("Page", pages)
    st.title("Lost Child Response Board")
    st.write("Welcome. Use this board to help reunite separated children with their caregivers.")

    page_functions = {
        "Caregiver": caregiver_page,
        "Register child": register_child,
        "Live board": live_board,
        "Report missing": report_missing,
        "Found a child": found_a_child,
        "Wristband lookup": wristband_lookup,
        "Reunify": reunify,
        "Audit & privacy": audit_privacy,
    }
    page_functions[page]()
