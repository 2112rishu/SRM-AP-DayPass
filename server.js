const express = require("express");
const path = require("path");

const { initializeApp, cert } = require("firebase-admin/app");
const {
    getFirestore,
    FieldValue
} = require("firebase-admin/firestore");
const { getAuth } = require("firebase-admin/auth");

const app = express();
const PORT = process.env.PORT || 3000;

console.log("🔥 SRM AP DAYPASS SERVER - ENTRY SYSTEM ENABLED");

// --------------------------------------------------
// FIREBASE ADMIN SETUP
// --------------------------------------------------

function getServiceAccount() {
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
        return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
    }

    return require("./firebase-service-account.json");
}

const serviceAccount = getServiceAccount();

initializeApp({
    credential: cert(serviceAccount)
});

const db = getFirestore();
const adminAuth = getAuth();

// --------------------------------------------------
// MIDDLEWARE
// --------------------------------------------------

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname)));

// --------------------------------------------------
// AUTH MIDDLEWARE
// --------------------------------------------------

async function requireAuth(req, res, next) {
    try {
        const authHeader = req.headers.authorization || "";

        if (!authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Authentication required."
            });
        }

        const token = authHeader.substring(7);

        const decodedToken = await adminAuth.verifyIdToken(token);

        req.user = decodedToken;

        next();
    } catch (error) {
        console.error("Authentication error:", error);

        return res.status(401).json({
            success: false,
            message: "Invalid or expired authentication token."
        });
    }
}

// --------------------------------------------------
// ADMIN MIDDLEWARE
// --------------------------------------------------

async function requireAdmin(req, res, next) {
    try {
        const doc = await db
            .collection("students")
            .doc(req.user.uid)
            .get();

        if (!doc.exists) {
            return res.status(403).json({
                success: false,
                message: "Admin profile not found."
            });
        }

        const user = doc.data();

        if (user.role !== "admin") {
            return res.status(403).json({
                success: false,
                message: "Admin access required."
            });
        }

        next();
    } catch (error) {
        console.error("Admin check error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to verify admin access."
        });
    }
}

// --------------------------------------------------
// HOME
// --------------------------------------------------

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// --------------------------------------------------
// API STATUS
// --------------------------------------------------

app.get("/api/status", (req, res) => {
    res.json({
        success: true,
        message: "SRM AP DayPass API is running."
    });
});

// --------------------------------------------------
// GET CURRENT USER
// --------------------------------------------------

app.get("/api/me", requireAuth, async (req, res) => {
    try {
        const doc = await db
            .collection("students")
            .doc(req.user.uid)
            .get();

        if (!doc.exists) {
            return res.status(404).json({
                success: false,
                message: "User profile not found."
            });
        }

        res.json({
            success: true,
            user: {
                uid: req.user.uid,
                ...doc.data()
            }
        });
    } catch (error) {
        console.error("/api/me error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to load user profile."
        });
    }
});

// --------------------------------------------------
// ADMIN - GET ALL STUDENTS
// --------------------------------------------------

app.get(
    "/api/admin/students",
    requireAuth,
    requireAdmin,
    async (req, res) => {
        try {
            const snapshot = await db
                .collection("students")
                .orderBy("createdAt", "desc")
                .get();

            const students = [];

            snapshot.forEach(doc => {
                students.push({
                    id: doc.id,
                    ...doc.data()
                });
            });

            res.json({
                success: true,
                students
            });
        } catch (error) {
            console.error("Get students error:", error);

            res.status(500).json({
                success: false,
                message: "Unable to load students."
            });
        }
    }
);

// --------------------------------------------------
// ADMIN - CREATE STUDENT
// --------------------------------------------------

app.post(
    "/api/students",
    requireAuth,
    requireAdmin,
    async (req, res) => {
        try {
            const {
                studentId,
                name,
                email,
                password,
                status
            } = req.body;

            if (!studentId || !name || !email || !password) {
                return res.status(400).json({
                    success: false,
                    message: "Student ID, name, email and password are required."
                });
            }

            // Check duplicate student ID
            const existing = await db
                .collection("students")
                .where("studentId", "==", studentId)
                .limit(1)
                .get();

            if (!existing.empty) {
                return res.status(409).json({
                    success: false,
                    message: "Student ID already exists."
                });
            }

            // Create Firebase Auth account
            const firebaseUser = await adminAuth.createUser({
                email,
                password,
                displayName: name
            });

            // Create Firestore profile
            await db
                .collection("students")
                .doc(firebaseUser.uid)
                .set({
                    studentId,
                    name,
                    email,
                    status: status || "Day Scholar",
                    role: "student",
                    accountStatus: "ACTIVE",
                    createdAt: FieldValue.serverTimestamp()
                });

            res.json({
                success: true,
                message: "Student account created successfully.",
                student: {
                    uid: firebaseUser.uid,
                    studentId,
                    name,
                    email
                }
            });
        } catch (error) {
            console.error("Create student error:", error);

            res.status(500).json({
                success: false,
                message: error.message || "Unable to create student."
            });
        }
    }
);

// --------------------------------------------------
// ADMIN - BLOCK / UNBLOCK STUDENT
// --------------------------------------------------

app.patch(
    "/api/students/:studentId/status",
    requireAuth,
    requireAdmin,
    async (req, res) => {
        try {
            const { studentId } = req.params;
            const { accountStatus } = req.body;

            if (!["ACTIVE", "BLOCKED"].includes(accountStatus)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid account status."
                });
            }

            const snapshot = await db
                .collection("students")
                .where("studentId", "==", studentId)
                .limit(1)
                .get();

            if (snapshot.empty) {
                return res.status(404).json({
                    success: false,
                    message: "Student not found."
                });
            }

            const doc = snapshot.docs[0];

            await doc.ref.update({
                accountStatus
            });

            await adminAuth.updateUser(doc.id, {
                disabled: accountStatus !== "ACTIVE"
            });

            res.json({
                success: true,
                message:
                    accountStatus === "ACTIVE"
                        ? "Student account activated."
                        : "Student account blocked."
            });
        } catch (error) {
            console.error("Student status error:", error);

            res.status(500).json({
                success: false,
                message: "Unable to update student status."
            });
        }
    }
);

// --------------------------------------------------
// GET TODAY'S DATE KEY
// India timezone: Asia/Kolkata
// --------------------------------------------------

function getIndiaDateKey() {
    return new Intl.DateTimeFormat("en-CA", {
        timeZone: "Asia/Kolkata",
        year: "numeric",
        month: "2-digit",
        day: "2-digit"
    }).format(new Date());
}

// --------------------------------------------------
// VERIFY QR + RECORD ENTRY
// MAXIMUM 3 SUCCESSFUL ENTRIES PER DAY
// --------------------------------------------------

app.post("/api/verify-qr", requireAuth, async (req, res) => {
    try {
        const { studentId } = req.body;

        if (!studentId) {
            return res.status(400).json({
                success: false,
                message: "Student ID is required."
            });
        }

        // Find student
        const snapshot = await db
            .collection("students")
            .where("studentId", "==", studentId)
            .limit(1)
            .get();

        if (snapshot.empty) {
            return res.status(404).json({
                success: false,
                message: "Student not found."
            });
        }

        const studentDoc = snapshot.docs[0];
        const student = studentDoc.data();

        // Check blocked account
        if (student.accountStatus !== "ACTIVE") {
            return res.status(403).json({
                success: false,
                message: "Student account is blocked.",
                student: {
                    studentId: student.studentId,
                    name: student.name,
                    email: student.email
                }
            });
        }

        const dateKey = getIndiaDateKey();

        /*
         * One counter document per student per day.
         *
         * Example:
         * entryCounters/SRMAP-STU-1001_2026-09-23
         */
        const counterId = `${student.studentId}_${dateKey}`;

        const counterRef = db
            .collection("entryCounters")
            .doc(counterId);

        const entryRef = db
            .collection("entries")
            .doc();

        let entryNumber;

        await db.runTransaction(async transaction => {
            const counterDoc = await transaction.get(counterRef);

            let currentCount = 0;

            if (counterDoc.exists) {
                currentCount = counterDoc.data().count || 0;
            }

            // Maximum 3 entries per day
            if (currentCount >= 3) {
                throw new Error("DAILY_LIMIT_REACHED");
            }

            entryNumber = currentCount + 1;

            // Update counter
            transaction.set(
                counterRef,
                {
                    studentId: student.studentId,
                    date: dateKey,
                    count: entryNumber,
                    updatedAt: FieldValue.serverTimestamp()
                },
                { merge: true }
            );

            // Create successful entry
            transaction.set(entryRef, {
                studentId: student.studentId,
                name: student.name,
                email: student.email || "",
                status: student.status || "",
                entryNumber,
                entryDate: dateKey,
                verificationStatus: "SUCCESS",
                verifiedBy: req.user.uid,
                createdAt: FieldValue.serverTimestamp()
            });
        });

        console.log(
            `✅ ENTRY SUCCESS: ${student.studentId} - Entry ${entryNumber}/3`
        );

        res.json({
            success: true,
            message: `Entry ${entryNumber} successful.`,
            entry: {
                entryNumber,
                entryLimit: 3,
                remainingEntries: 3 - entryNumber,
                studentId: student.studentId,
                name: student.name,
                date: dateKey
            }
        });

    } catch (error) {

        if (error.message === "DAILY_LIMIT_REACHED") {
            return res.status(429).json({
                success: false,
                message: "Daily entry limit reached. Maximum 3 entries allowed per day.",
                entryLimit: 3,
                remainingEntries: 0
            });
        }

        console.error("QR verification error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to verify QR code."
        });
    }
});

// --------------------------------------------------
// GET ENTRY HISTORY
// --------------------------------------------------

app.get("/api/entries", requireAuth, async (req, res) => {
    try {
        const snapshot = await db
            .collection("entries")
            .orderBy("createdAt", "desc")
            .limit(100)
            .get();

        const entries = [];

        snapshot.forEach(doc => {
            const data = doc.data();

            entries.push({
                id: doc.id,
                ...data
            });
        });

        res.json({
            success: true,
            entries
        });

    } catch (error) {
        console.error("Entry history error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to load entry history."
        });
    }
});

// --------------------------------------------------
// GET ENTRY HISTORY FOR PARTICULAR STUDENT
// --------------------------------------------------

app.get(
    "/api/entries/:studentId",
    requireAuth,
    async (req, res) => {
        try {
            const { studentId } = req.params;

            const snapshot = await db
                .collection("entries")
                .where("studentId", "==", studentId)
                .get();

            const entries = [];

            snapshot.forEach(doc => {
                entries.push({
                    id: doc.id,
                    ...doc.data()
                });
            });

            // Sort newest first
            entries.sort((a, b) => {
                const aTime = a.createdAt?.toMillis
                    ? a.createdAt.toMillis()
                    : 0;

                const bTime = b.createdAt?.toMillis
                    ? b.createdAt.toMillis()
                    : 0;

                return bTime - aTime;
            });

            res.json({
                success: true,
                entries
            });

        } catch (error) {
            console.error("Student entry history error:", error);

            res.status(500).json({
                success: false,
                message: "Unable to load student entry history."
            });
        }
    }
);

// --------------------------------------------------
// API 404
// --------------------------------------------------

app.use("/api", (req, res) => {
    res.status(404).json({
        success: false,
        message: "API route not found."
    });
});

// --------------------------------------------------
// ERROR HANDLER
// --------------------------------------------------

app.use((error, req, res, next) => {
    console.error("Server error:", error);

    res.status(500).json({
        success: false,
        message: "Internal server error."
    });
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 http://localhost:${PORT}`);
});