# QR Event Scanner

A simple FastAPI app to track event attendance via QR codes, with an admin panel for management.

**⚠️ Note:** This project is designed as a **quick event scanner** and is **not intended for production use**. It is meant for small-scale events or testing purposes. It does not include enterprise-level security, performance optimizations, or scalability features.

---

## Overview

This is a FastAPI-based web application for scanning and tracking event attendees using QR codes. It allows organizers to:

- Generate QR codes for attendees.
- Scan QR codes using a camera-enabled device.
- Record attendee information (name, description, event, timestamp, IP) into a local SQLite database.
- View recent scans in real-time.
- Manage simple admin features like blocked IPs, prohibited events, and password changes.

The application stores data locally in SQLite databases under the `data/` folder.

---

## Features

### Attendee Scanning

- Mobile-friendly event scanning interface.
- QR code scanning using the device camera.
- Records metadata: attendee name, description, event, timestamp, and IP address.
- Simple recent scans display.

### QR Code Generation

- Generate QR codes with attendee information.
- Submit generated QR codes directly to the system.

### Admin Panel

- Password-protected using HTTP Basic authentication.
- Add/remove prohibited events.
- Add/remove blocked IPs.
- View/export all scans as CSV.

### Event Management

- Homepage allows event selection.
- Dynamic pages for each event with live QR scanning.
- API endpoints for integration or retrieving events.

---

## Quick Start

1. **Build the Docker image**:

```bash
docker build -t event-scanner .
```

2. **Run the Docker container**:

```bash
docker run -d -p 80:80 --name event-scanner -v ./data:/app/data event-scanner
```

3. **Access the app**:

* Homepage: [http://127.0.0.1/](http://127.0.0.1/)
* Admin panel: [http://127.0.0.1/admin](http://127.0.0.1/admin)

  * Default username: `admin`
  * Default password: `admin`

4. **Create and scan QR codes**:

* Use the `/qr-gen` page to generate attendee QR codes.
* Scan QR codes in your selected event.

---

## Configuration & Storage

* **Favicon**: Ensure your `favicon.ico` is located in the `data/` folder to customize.
* **Databases**:

  * `data/activities.db` → Stores attendee scans.
  * `data/admin.db` → Stores admin credentials, prohibited events, and blocked IPs.
* **Prohibited Events**: Prevents certain events from being scanned or recorded.
* **Blocked IPs**: Prevents certain IPs from submitting scans.
* **Profanity Filtering**: Uses `better_profanity` to block events containing offensive words.

---

## API Endpoints

| Method | Endpoint                         | Description                                 |
| ------ | -------------------------------- | ------------------------------------------- |
| POST   | `/api/scan`                      | Submit a scan                               |
| GET    | `/api/recent`                    | Retrieve recent scans                       |
| GET    | `/api/events`                    | Retrieve all recorded events                |
| GET    | `/api/qr-gen`                    | Generate a QR code image from attendee data |
| POST   | `/admin/change-password`         | Change admin password                       |
| POST   | `/admin/add-prohibited-event`    | Add a prohibited event                      |
| POST   | `/admin/remove-prohibited-event` | Remove a prohibited event                   |
| POST   | `/admin/add-blocked-ip`          | Block an IP                                 |
| POST   | `/admin/remove-blocked-ip`       | Unblock an IP                               |
| GET    | `/admin/export-scans`            | Export all scans as CSV                     |
| GET    | `/admin/scans`                   | Retrieve recent scans for admin panel       |

Please refer to openAPI docs at `/docs` for detailed request/response formats.

---

## Security Considerations

* Uses **HTTP Basic Authentication** for the admin panel; suitable only for local-only events, not public internet.
* Passwords are hashed with **bcrypt**, but no SSL/TLS enforcement. This should be run behind HTTPS gateway to permit camera access.
* No input sanitization beyond profanity filtering; do not expose to untrusted users.
* No rate limiting or protection against brute-force attacks.
* SQLite databases are used; concurrency is limited.

---

## Why Use This?

This project is ideal for **small, temporary events** where you need:

* Quick attendee registration.
* Easy QR code generation and scanning.
* Minimal setup and zero external dependencies beyond Python.

**Do NOT use this for high-security or large-scale production events**.
