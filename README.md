# Adaptive Zero Trust Access Control System

Python + SQLite project that demonstrates:

- Continuous user verification (auto-refresh every few seconds)
- Adaptive risk scoring from context, device posture, and behavior
- Context-aware decisions (who, where, when, what)
- Least privilege enforcement via anomaly injection and automatic revocation

## Run locally

1. Create a virtual environment (optional but recommended).
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Start the app:

```bash
python app.py
```

4. Open:

```text
http://127.0.0.1:5000
```

SQLite database file is created automatically at `data/zero_trust.db`.
