const express = require("express");
const cors = require("cors");
const path = require("path");

console.log("🔥 THIS IS THE NEW SERVER.JS");

const { initializeApp, cert } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const { getAuth } = require("firebase-admin/auth");

const app = express();
const PORT = process.env.PORT || 3000;

/* =====================================================
   FIREBASE ADMIN SETUP
   ===================================================== */

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
const auth = getAuth();

/* =====================================================
   MIDDLEWARE
   ===================================================== */

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(__dirname));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

/* =====================================================
   SERVE FRONTEND FILES
   ===================================================== */

app.use(express.static(__dirname));

/* =====================================================
   HOME PAGE
   ===================================================== */

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

/* =====================================================
   API STATUS
   ===================================================== */

app.get("/api/status", (req, res) => {
    res.json({
        success: true,
        message: "SRM AP DayPass API is running."
    });
});

/* =====================================================
   VERIFY FIREBASE TOKEN
   ===================================================== */

async function verifyToken(req, res, next) {
    try {
        const authorization = req.headers.authorization || "";

        if (!authorization.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Authentication required."
            });
        }

        const token = authorization.substring(7);

        const decodedToken = await auth.verifyIdToken(token);

        req.user = decodedToken;

        next();

    } catch (error) {
        console.error("Token verification error:", error);

        return res.status(401).json({
            success: false,
            message: "Invalid or expired authentication token."
        });
    }
}

/* =====================================================
   VERIFY ADMIN
   ===================================================== */

async function verifyAdmin(req, res, next) {
    try {
        const userDoc = await db
            .collection("students")
            .doc(req.user.uid)
            .get();

        if (!userDoc.exists) {
            return res.status(403).json({
                success: false,
                message: "User profile not found."
            });
        }

        const userData = userDoc.data();

        if (userData.role !== "admin") {
            return res.status(403).json({
                success: false,
                message: "Admin access required."
            });
        }

        if (userData.accountStatus === "BLOCKED") {
            return res.status(403).json({
                success: false,
                message: "Account is blocked."
            });
        }

        next();

    } catch (error) {
        console.error("Admin verification error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to verify admin."
        });
    }
}

/* =====================================================
   GET CURRENT USER PROFILE
   ===================================================== */

app.get("/api/me", verifyToken, async (req, res) => {
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
        console.error("Profile error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to load profile."
        });
    }
});

/* =====================================================
   ADMIN - ADD STUDENT
   ===================================================== */

app.post("/api/admin/students", verifyToken, verifyAdmin, async (req, res) => {
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

        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message: "Password must contain at least 6 characters."
            });
        }

        /* Check duplicate Student ID */

        const existingStudent = await db
            .collection("students")
            .where("studentId", "==", studentId)
            .limit(1)
            .get();

        if (!existingStudent.empty) {
            return res.status(400).json({
                success: false,
                message: "Student ID already exists."
            });
        }

        /* Create Firebase Auth account */

        let firebaseUser;

        try {
            firebaseUser = await auth.createUser({
                email: email,
                password: password,
                displayName: name
            });

        } catch (error) {
            console.error("Firebase Auth error:", error);

            return res.status(400).json({
                success: false,
                message: error.message
            });
        }

        /* Create Firestore profile */

        try {
            await db
                .collection("students")
                .doc(firebaseUser.uid)
                .set({
                    studentId: studentId,
                    name: name,
                    email: email,
                    status: status || "Day Scholar",
                    role: "student",
                    accountStatus: "ACTIVE",
                    createdAt: FieldValue.serverTimestamp()
                });

            res.json({
                success: true,
                message: "Student created successfully.",
                uid: firebaseUser.uid
            });

        } catch (error) {

            /* Remove Auth account if Firestore fails */

            try {
                await auth.deleteUser(firebaseUser.uid);
            } catch (deleteError) {
                console.error("Cleanup error:", deleteError);
            }

            throw error;
        }

    } catch (error) {
        console.error("Create student error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to create student."
        });
    }
});

/* =====================================================
   ADMIN - GET STUDENTS
   ===================================================== */

app.get("/api/students", verifyToken, verifyAdmin, async (req, res) => {
    try {

        const snapshot = await db
            .collection("students")
            .where("role", "==", "student")
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
            students: students
        });

    } catch (error) {
        console.error("Get students error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to load students."
        });
    }
});

/* =====================================================
   ADMIN - BLOCK / UNBLOCK STUDENT
   ===================================================== */

app.patch(
    "/api/students/:studentId/status",
    verifyToken,
    verifyAdmin,
    async (req, res) => {

        try {

            const studentId = req.params.studentId;
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

            const studentDoc = snapshot.docs[0];

            await studentDoc.ref.update({
                accountStatus: accountStatus
            });

            res.json({
                success: true,
                message:
                    accountStatus === "BLOCKED"
                        ? "Student blocked successfully."
                        : "Student unblocked successfully."
            });

        } catch (error) {
            console.error("Status update error:", error);

            res.status(500).json({
                success: false,
                message: "Unable to update student status."
            });
        }
    }
);

/* =====================================================
   VERIFY DAYPASS QR
   ===================================================== */

app.post("/api/verify-qr", verifyToken, async (req, res) => {
    try {

        const { qrData } = req.body;

        if (!qrData) {
            return res.status(400).json({
                success: false,
                message: "QR data is required."
            });
        }

        const parts = qrData.split("|");

        if (
            parts.length !== 3 ||
            parts[0] !== "SRMAP"
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid SRM AP DayPass QR."
            });
        }

        const encodedStudentId = parts[1];
        const qrTimeSlot = Number(parts[2]);

        let studentId;

        try {
            studentId = Buffer
                .from(encodedStudentId, "base64")
                .toString("utf8");
        } catch (error) {
            return res.status(400).json({
                success: false,
                message: "Invalid QR data."
            });
        }

        const currentTimeSlot =
            Math.floor(Date.now() / 1000 / 30);

        if (
            qrTimeSlot !== currentTimeSlot &&
            qrTimeSlot !== currentTimeSlot - 1
        ) {
            return res.status(400).json({
                success: false,
                message: "QR code has expired."
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

        const studentDoc = snapshot.docs[0];
        const student = studentDoc.data();

        if (student.accountStatus === "BLOCKED") {
            return res.status(403).json({
                success: false,
                message: "Student account is blocked."
            });
        }

        res.json({
            success: true,
            message: "QR verified successfully.",
            student: student
        });

    } catch (error) {

        console.error("QR verification error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to verify QR code."
        });
    }
});

/* =====================================================
   SAVE ENTRY
   ===================================================== */

app.post("/api/entries", verifyToken, async (req, res) => {
    try {

        const {
            studentId,
            studentName,
            entryType
        } = req.body;

        if (!studentId) {
            return res.status(400).json({
                success: false,
                message: "Student ID is required."
            });
        }

        const entry = {
            studentId: studentId,
            studentName: studentName || "",
            entryType: entryType || "ENTRY",
            scannedBy: req.user.uid,
            timestamp: FieldValue.serverTimestamp()
        };

        const document = await db
            .collection("entries")
            .add(entry);

        res.json({
            success: true,
            message: "Entry recorded successfully.",
            entryId: document.id
        });

    } catch (error) {

        console.error("Save entry error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to save entry."
        });
    }
});

/* =====================================================
   ADMIN - GET ALL ENTRIES
   ===================================================== */

app.get("/api/entries", verifyToken, verifyAdmin, async (req, res) => {
    try {

        const snapshot = await db
            .collection("entries")
            .limit(200)
            .get();

        const entries = [];

        snapshot.forEach(doc => {
            entries.push({
                id: doc.id,
                ...doc.data()
            });
        });

        entries.sort((a, b) => {

            const timeA =
                a.timestamp && a.timestamp.toMillis
                    ? a.timestamp.toMillis()
                    : 0;

            const timeB =
                b.timestamp && b.timestamp.toMillis
                    ? b.timestamp.toMillis()
                    : 0;

            return timeB - timeA;
        });

        res.json({
            success: true,
            entries: entries
        });

    } catch (error) {

        console.error("Get entries error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to load entries."
        });
    }
});

/* =====================================================
   STUDENT - GET OWN HISTORY
   ===================================================== */

app.get("/api/entries/:studentId", verifyToken, async (req, res) => {
    try {

        const requestedStudentId =
            req.params.studentId;

        const profile = await db
            .collection("students")
            .doc(req.user.uid)
            .get();

        if (!profile.exists) {
            return res.status(404).json({
                success: false,
                message: "Profile not found."
            });
        }

        const user = profile.data();

        if (
            user.role !== "admin" &&
            user.studentId !== requestedStudentId
        ) {
            return res.status(403).json({
                success: false,
                message: "Access denied."
            });
        }

        const snapshot = await db
            .collection("entries")
            .where("studentId", "==", requestedStudentId)
            .get();

        const entries = [];

        snapshot.forEach(doc => {
            entries.push({
                id: doc.id,
                ...doc.data()
            });
        });

        entries.sort((a, b) => {

            const timeA =
                a.timestamp && a.timestamp.toMillis
                    ? a.timestamp.toMillis()
                    : 0;

            const timeB =
                b.timestamp && b.timestamp.toMillis
                    ? b.timestamp.toMillis()
                    : 0;

            return timeB - timeA;
        });

        res.json({
            success: true,
            entries: entries
        });

    } catch (error) {

        console.error("History error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to load history."
        });
    }
});

/* =====================================================
   API 404
   ===================================================== */

app.use("/api", (req, res) => {
    res.status(404).json({
        success: false,
        message: "API endpoint not found."
    });
});

/* =====================================================
   GENERAL ERROR HANDLER
   ===================================================== */

app.use((error, req, res, next) => {

    console.error("Server error:", error);

    res.status(500).json({
        success: false,
        message: "Server error."
    });
});

/* =====================================================
   START SERVER
   ===================================================== */

app.listen(PORT, "0.0.0.0", () => {

    console.log(
        `SRM AP DayPass server running on http://localhost:${PORT}`
    );

});