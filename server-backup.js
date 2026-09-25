"use strict";

require("dotenv").config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const admin = require("firebase-admin");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const QR_SECRET = process.env.DAYPASS_QR_SECRET;

const QR_TTL = 30;
const DAILY_LIMIT = 3;

if (!QR_SECRET || QR_SECRET.length < 48) {
    console.error("❌ DAYPASS_QR_SECRET is missing or too short.");
    process.exit(1);
}

/* =========================================================
   FIREBASE
========================================================= */

function initializeFirebase() {
    try {
        return admin.app();
    } catch (_) {
        // Firebase has not been initialized.
    }

    let serviceAccount;

    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
        try {
            serviceAccount = JSON.parse(
                process.env.FIREBASE_SERVICE_ACCOUNT_JSON
            );
        } catch (error) {
            console.error("❌ Invalid FIREBASE_SERVICE_ACCOUNT_JSON");
            process.exit(1);
        }
    } else {
        const file = path.join(
            __dirname,
            "firebase-service-account.json"
        );

        if (!fs.existsSync(file)) {
            console.error(
                "❌ firebase-service-account.json not found."
            );
            process.exit(1);
        }

        try {
            serviceAccount = JSON.parse(
                fs.readFileSync(file, "utf8")
            );
        } catch (error) {
            console.error(
                "❌ Could not read firebase-service-account.json"
            );
            process.exit(1);
        }
    }

    return admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

initializeFirebase();

const db = admin.firestore();
const auth = admin.auth();

console.log("✅ Firebase connected");

/* =========================================================
   EXPRESS
========================================================= */

app.disable("x-powered-by");

app.use(
    helmet({
        contentSecurityPolicy: false
    })
);

app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

/* =========================================================
   RATE LIMITING
========================================================= */

app.use(
    rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 300,
        standardHeaders: true,
        legacyHeaders: false
    })
);

const qrLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false
});

/* =========================================================
   HELPERS
========================================================= */

function clean(value, length = 500) {
    if (value === undefined || value === null) {
        return "";
    }

    return String(value).trim().slice(0, length);
}

function getToday() {
    return new Intl.DateTimeFormat("en-CA", {
        timeZone: "Asia/Kolkata",
        year: "numeric",
        month: "2-digit",
        day: "2-digit"
    }).format(new Date());
}

function sameConstantTime(a, b) {
    try {
        const x = Buffer.from(a);
        const y = Buffer.from(b);

        if (x.length !== y.length) {
            return false;
        }

        return crypto.timingSafeEqual(x, y);
    } catch (_) {
        return false;
    }
}

/* =========================================================
   AUDIT LOG
========================================================= */

async function audit(
    actorUid,
    actorRole,
    action,
    targetUid = null,
    details = {}
) {
    try {
        await db.collection("auditLogs").add({
            actorUid,
            actorRole,
            action,
            targetUid,
            details,
            createdAt:
                admin.firestore.FieldValue.serverTimestamp()
        });
    } catch (error) {
        console.error("Audit error:", error.message);
    }
}

/* =========================================================
   AUTHENTICATION
========================================================= */

async function authenticate(req, res, next) {
    try {
        const header = req.headers.authorization || "";

        if (!header.startsWith("Bearer ")) {
            return res.status(401).json({
                error: "Authentication required."
            });
        }

        const token = header.substring(7).trim();

        const decoded = await auth.verifyIdToken(
            token,
            true
        );

        const uid = decoded.uid;

        const profileSnap = await db
            .collection("students")
            .doc(uid)
            .get();

        if (!profileSnap.exists) {
            return res.status(403).json({
                error: "User profile not found."
            });
        }

        const profile = profileSnap.data();

        if (
            (profile.accountStatus || "ACTIVE") !==
            "ACTIVE"
        ) {
            return res.status(403).json({
                error: "This account is blocked."
            });
        }

        req.user = {
            uid,
            email: decoded.email || profile.email || "",
            name: profile.name || decoded.name || "",
            studentId: profile.studentId || "",
            studentType: profile.studentType || "",
            role: profile.role || "STUDENT",
            accountStatus:
                profile.accountStatus || "ACTIVE"
        };

        next();
    } catch (error) {
        console.error(
            "Authentication error:",
            error.message
        );

        res.status(401).json({
            error: "Authentication failed."
        });
    }
}

function requireRoles(...roles) {
    return (req, res, next) => {
        if (
            !req.user ||
            !roles.includes(req.user.role)
        ) {
            return res.status(403).json({
                error: "You are not authorized."
            });
        }

        next();
    };
}

/* =========================================================
   QR CREATION
========================================================= */

function createSignature(data) {
    return crypto
        .createHmac("sha256", QR_SECRET)
        .update(data)
        .digest("base64url");
}

function createQR(user) {
    const now = Math.floor(Date.now() / 1000);

    const payload = {
        v: 1,
        uid: user.uid,
        studentId: user.studentId,
        iat: now,
        exp: now + QR_TTL,
        nonce: crypto.randomBytes(16).toString("hex")
    };

    const encoded = Buffer.from(
        JSON.stringify(payload)
    ).toString("base64url");

    const signature = createSignature(encoded);

    return {
        token: `${encoded}.${signature}`,
        issuedAt: now,
        expiresAt: now + QR_TTL
    };
}

function verifyQR(token) {
    if (!token) {
        throw new Error("QR code is required.");
    }

    const parts = token.split(".");

    if (parts.length !== 2) {
        throw new Error("Invalid QR code.");
    }

    const encoded = parts[0];
    const signature = parts[1];

    const expected = createSignature(encoded);

    if (!sameConstantTime(signature, expected)) {
        throw new Error("Invalid QR signature.");
    }

    let payload;

    try {
        payload = JSON.parse(
            Buffer.from(
                encoded,
                "base64url"
            ).toString("utf8")
        );
    } catch (_) {
        throw new Error("Invalid QR data.");
    }

    const now = Math.floor(Date.now() / 1000);

    if (payload.v !== 1) {
        throw new Error("Unsupported QR version.");
    }

    if (
        !payload.uid ||
        !payload.studentId ||
        !payload.nonce
    ) {
        throw new Error("Incomplete QR code.");
    }

    if (payload.exp <= now) {
        throw new Error("QR code has expired.");
    }

    if (payload.iat > now + 5) {
        throw new Error("Invalid QR issue time.");
    }

    if (
        payload.exp - payload.iat >
        QR_TTL + 5
    ) {
        throw new Error("Invalid QR lifetime.");
    }

    return payload;
}

/* =========================================================
   STATUS
========================================================= */

app.get("/api/status", (req, res) => {
    res.json({
        success: true,
        status: "online",
        environment:
            process.env.NODE_ENV || "development",
        time: new Date().toISOString()
    });
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
    "/api/me",
    authenticate,
    async (req, res) => {
        res.json({
            success: true,
            user: req.user
        });
    }
);

/* =========================================================
   STUDENT QR
========================================================= */

async function generateQR(req, res) {
    try {
        if (req.user.role !== "STUDENT") {
            return res.status(403).json({
                error:
                    "Only students can generate QR codes."
            });
        }

        /*
         * Only one Firestore filter is used.
         * This avoids the composite-index problem.
         */

        const snapshot = await db
            .collection("entries")
            .where(
                "studentUid",
                "==",
                req.user.uid
            )
            .get();

        const today = getToday();

        let todayCount = 0;

        snapshot.forEach(doc => {
            const data = doc.data();

            if (data.dayKey === today) {
                todayCount++;
            }
        });

        if (todayCount >= DAILY_LIMIT) {
            return res.status(429).json({
                error:
                    "Daily entry limit reached.",
                dailyCount: todayCount,
                dailyLimit: DAILY_LIMIT
            });
        }

        const qr = createQR(req.user);

        await audit(
            req.user.uid,
            req.user.role,
            "QR_GENERATED",
            req.user.uid
        );

        res.json({
            success: true,

            qrData: qr.token,

            token: qr.token,

            issuedAt: qr.issuedAt,

            expiresAt: qr.expiresAt,

            qr: {
                token: qr.token,
                issuedAt: new Date(
                    qr.issuedAt * 1000
                ).toISOString(),
                expiresAt: new Date(
                    qr.expiresAt * 1000
                ).toISOString()
            },

            dailyCount: todayCount,

            dailyLimit: DAILY_LIMIT
        });
    } catch (error) {
        console.error(
            "QR generation error:",
            error
        );

        res.status(500).json({
            error:
                "Unable to generate QR code."
        });
    }
}

app.get(
    "/api/qr",
    qrLimiter,
    authenticate,
    generateQR
);

app.post(
    "/api/qr",
    qrLimiter,
    authenticate,
    generateQR
);

/* =========================================================
   VERIFY QR - SECURITY
========================================================= */

app.post(
    "/api/verify-qr",
    qrLimiter,
    authenticate,
    requireRoles(
        "SECURITY",
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {
        try {
            const token = clean(
                req.body.qrData ||
                req.body.token ||
                req.body.qr,
                10000
            );

            const payload = verifyQR(token);

            const studentSnap = await db
                .collection("students")
                .doc(payload.uid)
                .get();

            if (!studentSnap.exists) {
                throw new Error(
                    "Student account not found."
                );
            }

            const student =
                studentSnap.data();

            if (
                (student.accountStatus ||
                    "ACTIVE") !== "ACTIVE"
            ) {
                throw new Error(
                    "Student account is blocked."
                );
            }

            if (
                clean(student.studentId) !==
                clean(payload.studentId)
            ) {
                throw new Error(
                    "Student ID verification failed."
                );
            }

            const today = getToday();

            const result =
                await db.runTransaction(
                    async transaction => {
                        const nonceRef =
                            db
                                .collection(
                                    "usedQRNonces"
                                )
                                .doc(
                                    payload.nonce
                                );

                        const nonceSnap =
                            await transaction.get(
                                nonceRef
                            );

                        if (nonceSnap.exists) {
                            throw new Error(
                                "This QR code has already been used."
                            );
                        }

                        const entriesSnap =
                            await db
                                .collection(
                                    "entries"
                                )
                                .where(
                                    "studentUid",
                                    "==",
                                    payload.uid
                                )
                                .get();

                        let todayCount = 0;

                        entriesSnap.forEach(
                            doc => {
                                if (
                                    doc.data()
                                        .dayKey ===
                                    today
                                ) {
                                    todayCount++;
                                }
                            }
                        );

                        if (
                            todayCount >=
                            DAILY_LIMIT
                        ) {
                            throw new Error(
                                "Student has reached the daily entry limit."
                            );
                        }

                        const entryRef =
                            db
                                .collection(
                                    "entries"
                                )
                                .doc();

                        transaction.create(
                            nonceRef,
                            {
                                uid:
                                    payload.uid,
                                usedAt:
                                    admin.firestore
                                        .FieldValue
                                        .serverTimestamp(),
                                expiresAt:
                                    payload.exp
                            }
                        );

                        transaction.create(
                            entryRef,
                            {
                                studentUid:
                                    payload.uid,

                                studentId:
                                    student.studentId ||
                                    "",

                                studentName:
                                    student.name ||
                                    "",

                                studentType:
                                    student.studentType ||
                                    "",

                                verifiedBy:
                                    req.user.uid,

                                verifiedByRole:
                                    req.user.role,

                                dayKey:
                                    today,

                                status:
                                    "ALLOWED",

                                createdAt:
                                    admin.firestore
                                        .FieldValue
                                        .serverTimestamp()
                            }
                        );

                        return {
                            entryId:
                                entryRef.id,

                            dailyCount:
                                todayCount + 1
                        };
                    }
                );

            await audit(
                req.user.uid,
                req.user.role,
                "ENTRY_ALLOWED",
                payload.uid,
                {
                    studentId:
                        student.studentId ||
                        "",
                    entryId:
                        result.entryId
                }
            );

            res.json({
                success: true,

                message:
                    "Entry allowed.",

                student: {
                    uid:
                        payload.uid,

                    studentId:
                        student.studentId ||
                        "",

                    name:
                        student.name ||
                        "",

                    studentType:
                        student.studentType ||
                        "",

                    accountStatus:
                        student.accountStatus ||
                        "ACTIVE"
                },

                entry: {
                    entryId:
                        result.entryId,

                    dailyCount:
                        result.dailyCount,

                    dailyLimit:
                        DAILY_LIMIT
                }
            });
        } catch (error) {
            console.error(
                "QR verification error:",
                error
            );

            res.status(400).json({
                error:
                    error.message ||
                    "QR verification failed."
            });
        }
    }
);

/* =========================================================
   STUDENT HISTORY
========================================================= */

app.get(
    "/api/entries/:studentId",
    authenticate,
    async (req, res) => {
        try {
            const studentId = clean(
                req.params.studentId,
                100
            );

            if (
                req.user.role === "STUDENT" &&
                studentId !== req.user.studentId
            ) {
                return res.status(403).json({
                    error:
                        "You can only view your own history."
                });
            }

            const snapshot = await db
                .collection("entries")
                .where(
                    "studentId",
                    "==",
                    studentId
                )
                .get();

            const entries =
                snapshot.docs
                    .map(doc => ({
                        id: doc.id,
                        ...doc.data()
                    }))
                    .sort(
                        (a, b) => {
                            const aTime =
                                a.createdAt &&
                                typeof a.createdAt
                                    .toMillis ===
                                    "function"
                                    ? a.createdAt.toMillis()
                                    : 0;

                            const bTime =
                                b.createdAt &&
                                typeof b.createdAt
                                    .toMillis ===
                                    "function"
                                    ? b.createdAt.toMillis()
                                    : 0;

                            return (
                                bTime -
                                aTime
                            );
                        }
                    )
                    .slice(0, 100);

            res.json({
                success: true,
                entries
            });
        } catch (error) {
            console.error(
                "History error:",
                error
            );

            res.status(500).json({
                error:
                    "Unable to load entry history."
            });
        }
    }
);

/* =========================================================
   STAFF HISTORY
========================================================= */

app.get(
    "/api/admin/entries",
    authenticate,
    requireRoles(
        "SECURITY",
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {
        try {
            /*
             * No orderBy here.
             * This avoids composite-index requirements.
             */

            const snapshot = await db
                .collection("entries")
                .limit(200)
                .get();

            const entries =
                snapshot.docs
                    .map(doc => ({
                        id: doc.id,
                        ...doc.data()
                    }))
                    .sort(
                        (a, b) => {
                            const aTime =
                                a.createdAt &&
                                typeof a.createdAt
                                    .toMillis ===
                                    "function"
                                    ? a.createdAt.toMillis()
                                    : 0;

                            const bTime =
                                b.createdAt &&
                                typeof b.createdAt
                                    .toMillis ===
                                    "function"
                                    ? b.createdAt.toMillis()
                                    : 0;

                            return (
                                bTime -
                                aTime
                            );
                        }
                    );

            res.json({
                success: true,
                entries
            });
        } catch (error) {
            console.error(
                "Staff history error:",
                error
            );

            res.status(500).json({
                error:
                    "Unable to load entry history."
            });
        }
    }
);

/* =========================================================
   CREATE STUDENT
========================================================= */

app.post(
    "/api/students",
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {
        try {
            const email = clean(
                req.body.email,
                200
            );

            const password = String(
                req.body.password || ""
            );

            const studentId = clean(
                req.body.studentId,
                100
            );

            const name = clean(
                req.body.name,
                200
            );

            const studentType = clean(
                req.body.studentType,
                100
            );

            if (
                !email ||
                !studentId ||
                !name ||
                password.length < 8
            ) {
                return res.status(400).json({
                    error:
                        "Valid email, password, student ID and name are required."
                });
            }

            const user =
                await auth.createUser({
                    email,
                    password,
                    displayName: name
                });

            await db
                .collection("students")
                .doc(user.uid)
                .set({
                    uid: user.uid,
                    email,
                    studentId,
                    name,
                    studentType,
                    role: "STUDENT",
                    accountStatus:
                        "ACTIVE",
                    createdAt:
                        admin.firestore
                            .FieldValue
                            .serverTimestamp()
                });

            await audit(
                req.user.uid,
                req.user.role,
                "STUDENT_CREATED",
                user.uid,
                { studentId }
            );

            res.json({
                success: true,
                message:
                    "Student created successfully.",
                uid: user.uid
            });
        } catch (error) {
            console.error(
                "Create student error:",
                error
            );

            res.status(400).json({
                error:
                    error.message ||
                    "Could not create student."
            });
        }
    }
);

/* =========================================================
   CREATE STAFF
========================================================= */

app.post(
    "/api/admins",
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {
        try {
            const email = clean(
                req.body.email,
                200
            );

            const password = String(
                req.body.password || ""
            );

            const name = clean(
                req.body.name,
                200
            );

            const role = clean(
                req.body.role,
                50
            ).toUpperCase();

            if (
                ![
                    "SECURITY",
                    "ADMIN",
                    "SUPER_ADMIN"
                ].includes(role)
            ) {
                return res.status(400).json({
                    error:
                        "Invalid staff role."
                });
            }

            if (
                req.user.role !==
                    "SUPER_ADMIN" &&
                role === "SUPER_ADMIN"
            ) {
                return res.status(403).json({
                    error:
                        "Only SUPER_ADMIN can create SUPER_ADMIN accounts."
                });
            }

            if (
                !email ||
                !name ||
                password.length < 8
            ) {
                return res.status(400).json({
                    error:
                        "Valid name, email and password are required."
                });
            }

            const user =
                await auth.createUser({
                    email,
                    password,
                    displayName: name
                });

            await db
                .collection("students")
                .doc(user.uid)
                .set({
                    uid: user.uid,
                    email,
                    name,
                    studentId:
                        `STAFF-${user.uid.slice(
                            0,
                            8
                        )}`,
                    studentType:
                        "STAFF",
                    role,
                    accountStatus:
                        "ACTIVE",
                    createdAt:
                        admin.firestore
                            .FieldValue
                            .serverTimestamp()
                });

            await audit(
                req.user.uid,
                req.user.role,
                "STAFF_CREATED",
                user.uid,
                { role }
            );

            res.json({
                success: true,
                message:
                    "Staff account created.",
                uid: user.uid,
                role
            });
        } catch (error) {
            console.error(
                "Create staff error:",
                error
            );

            res.status(400).json({
                error:
                    error.message ||
                    "Could not create staff."
            });
        }
    }
);

/* =========================================================
   STAFF LIST
========================================================= */

app.get(
    "/api/admin/staff",
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {
        try {
            const snapshot =
                await db
                    .collection(
                        "students"
                    )
                    .where(
                        "role",
                        "in",
                        [
                            "SECURITY",
                            "ADMIN",
                            "SUPER_ADMIN"
                        ]
                    )
                    .get();

            const staff =
                snapshot.docs.map(
                    doc => ({
                        uid: doc.id,
                        ...doc.data()
                    })
                );

            res.json({
                success: true,
                staff
            });
        } catch (error) {
            console.error(
                "Staff list error:",
                error
            );

            res.status(500).json({
                error:
                    "Unable to load staff."
            });
        }
    }
);

/* =========================================================
   BLOCK / UNBLOCK
========================================================= */

app.post(
    "/api/users/:uid/status",
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {
        try {
            const uid = clean(
                req.params.uid,
                200
            );

            const status = clean(
                req.body.status,
                50
            ).toUpperCase();

            if (
                ![
                    "ACTIVE",
                    "BLOCKED"
                ].includes(status)
            ) {
                return res.status(400).json({
                    error:
                        "Invalid account status."
                });
            }

            const ref = db
                .collection("students")
                .doc(uid);

            const snap =
                await ref.get();

            if (!snap.exists) {
                return res.status(404).json({
                    error:
                        "User not found."
                });
            }

            const target =
                snap.data();

            if (
                target.role ===
                    "SUPER_ADMIN" &&
                req.user.role !==
                    "SUPER_ADMIN"
            ) {
                return res.status(403).json({
                    error:
                        "Only SUPER_ADMIN can modify SUPER_ADMIN."
                });
            }

            await ref.update({
                accountStatus:
                    status,
                updatedAt:
                    admin.firestore
                        .FieldValue
                        .serverTimestamp()
            });

            await audit(
                req.user.uid,
                req.user.role,
                status === "BLOCKED"
                    ? "USER_BLOCKED"
                    : "USER_UNBLOCKED",
                uid
            );

            res.json({
                success: true,
                message:
                    status === "BLOCKED"
                        ? "User blocked."
                        : "User unblocked."
            });
        } catch (error) {
            console.error(
                "Status error:",
                error
            );

            res.status(500).json({
                error:
                    "Unable to update account status."
            });
        }
    }
);

/* =========================================================
   AUDIT LOGS
========================================================= */

app.get(
    "/api/admin/audit-logs",
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {
        try {
            const snapshot =
                await db
                    .collection(
                        "auditLogs"
                    )
                    .limit(100)
                    .get();

            const logs =
                snapshot.docs
                    .map(doc => ({
                        id: doc.id,
                        ...doc.data()
                    }))
                    .sort(
                        (a, b) => {
                            const aTime =
                                a.createdAt &&
                                typeof a.createdAt
                                    .toMillis ===
                                    "function"
                                    ? a.createdAt.toMillis()
                                    : 0;

                            const bTime =
                                b.createdAt &&
                                typeof b.createdAt
                                    .toMillis ===
                                    "function"
                                    ? b.createdAt.toMillis()
                                    : 0;

                            return (
                                bTime -
                                aTime
                            );
                        }
                    );

            res.json({
                success: true,
                logs
            });
        } catch (error) {
            console.error(
                "Audit list error:",
                error
            );

            res.status(500).json({
                error:
                    "Unable to load audit logs."
            });
        }
    }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/api/logout",
    authenticate,
    async (req, res) => {
        await audit(
            req.user.uid,
            req.user.role,
            "LOGOUT"
        );

        res.json({
            success: true
        });
    }
);

/* =========================================================
   WEBSITE
========================================================= */

app.use(
    express.static(__dirname, {
        extensions: ["html"]
    })
);

/* =========================================================
   API 404
========================================================= */

app.use("/api", (req, res) => {
    res.status(404).json({
        error:
            "API endpoint not found."
    });
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (error, req, res, next) => {
        console.error(
            "Global error:",
            error
        );

        if (res.headersSent) {
            return next(error);
        }

        res.status(500).json({
            error:
                "Internal server error."
        });
    }
);

/* =========================================================
   START SERVER
========================================================= */

const server = app.listen(
    PORT,
    "0.0.0.0",
    () => {
        console.log("");
        console.log(
            "========================================"
        );
        console.log(
            "       SRM AP DAYPASS SERVER"
        );
        console.log(
            "========================================"
        );
        console.log(
            `✅ Server running on port ${PORT}`
        );
        console.log(
            `🌐 http://localhost:${PORT}`
        );
        console.log(
            "🔐 Firebase authentication enabled"
        );
        console.log(
            "🎫 Student QR enabled"
        );
        console.log(
            "🛡️ Security verification enabled"
        );
        console.log(
            "📋 Entry history enabled"
        );
        console.log(
            "========================================"
        );
        console.log("");
    }
);

server.on(
    "error",
    error => {
        console.error(
            "❌ Server error:",
            error
        );

        if (
            error.code ===
            "EADDRINUSE"
        ) {
            console.error(
                `Port ${PORT} is already in use.`
            );
        }

        process.exit(1);
    }
);

process.on(
    "SIGINT",
    () => {
        console.log(
            "\nShutting down server..."
        );

        server.close(
            () => process.exit(0)
        );
    }
);

process.on(
    "SIGTERM",
    () => {
        server.close(
            () => process.exit(0)
        );
    }
);