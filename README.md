# SRM AP DayPass

Full-stack demo application for a digital student DayPass workflow.

## Features

- Student email/password login
- Admin email/password login
- Admin creates student accounts
- Time-based QR DayPass
- QR camera scanning
- QR image upload
- QR verification
- Entry recording
- Student entry history
- Admin entry history
- Student block/unblock
- Firebase Authentication
- Cloud Firestore
- Express backend
- Same-origin API for public deployment

## Project files

- index.html
- student-login.html
- admin-login.html
- dashboard.html
- security.html
- history.html
- admin.html
- firebase-config.js
- style.css
- server.js
- package.json

## Local setup

1. Install Node.js.
2. Put `firebase-service-account.json` in the project root.
3. Put your Firebase Web App configuration in `firebase-config.js`.
4. Run:

```bash
npm install
npm start
```

5. Open:

```text
http://localhost:3000
```

## Firebase

Enable:

- Authentication → Email/Password
- Cloud Firestore

Create an admin Firebase Auth user and matching Firestore document in:

```text
students/{ADMIN_UID}
```

with:

```text
studentId: SRMAP-ADM-001
name: Admin Name
email: admin@example.com
role: admin
accountStatus: ACTIVE
```

Never upload `firebase-service-account.json` to GitHub.

## Public deployment

This project is designed to be deployed as one Render Web Service.

Build command:

```text
npm install
```

Start command:

```text
npm start
```

Add Render secret:

```text
FIREBASE_SERVICE_ACCOUNT_JSON
```

with the complete service-account JSON.

After deployment, use the Render HTTPS URL from any network/Wi-Fi.

## Important

This is a student/hackathon demonstration project and is not an official SRM AP authentication or access-control system.
