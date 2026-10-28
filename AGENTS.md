# Project Rules

Project: "Lost Child Response Board", a Streamlit web app that helps event staff find
and safely reunite a separated child with their caregiver at crowded events.

Rules:
- Python 3.9+, Streamlit only for UI, SQLite (`sqlite3` module) for storage.
- Keep the code in a single file `app.py` unless I ask to split it.
- Never show personal data (name, phone, photo) on any public page.
- Roles: lead, staff, volunteer. Volunteers must never see caregiver phone or photos.
- Log important actions to an audit table.
- After every change, run `python -m py_compile app.py` and fix any errors.
- Keep explanations short. Tell me what you changed and how to test it.
