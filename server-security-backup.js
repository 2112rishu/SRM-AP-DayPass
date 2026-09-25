// ============================================================
// SRM AP DAYPASS / ENTRYPASS - SECURE BACKEND
// ============================================================

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const {
  initializeApp,
  cert,
  getApps
} = require("firebase-admin/app");

const {
  getAuth
} = require("firebase-admin/auth");

const {
  getFirestore,
  FieldValue
} = require("firebase-admin/firestore");

// ============================================================
// APP CONFIG
// ============================================================

const app = express();

const PORT = Number(process.env.PORT || 3000);

const QR_TTL = 30; // seconds
const DAILY_LIMIT = 3;

const QR_SECRET = process.env.DAYPASS_QR_SECRET;

if (!QR_SECRET || QR_SECRET.length < 48) {
  console.error(
    "❌ DAYPASS_QR_SECRET is missing or shorter than 48 characters."
  );
  process.exit(1);
}

// ============================================================
// FIREBASE INITIALIZATION
// ============================================================

let serviceAccount;

try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    serviceAccount = JSON.parse(
      process.env.FIREBASE_SERVICE_ACCOUNT_JSON
    );
  } else {
    const serviceAccountPath = path.join(
      __dirname,
      "firebase-service-account.json"
    );

    if (!fs.existsSync(serviceAccountPath)) {
      throw new Error(
        "firebase-service-account.json not found."
      );
    }

    serviceAccount = require(serviceAccountPath);
  }
} catch (error) {
  console.error("❌ Firebase service account error:");
  console.error(error.message);
  process.exit(1);
}

if (!getApps().length) {
  initializeApp({
    credential: cert(serviceAccount)
  });
}

const auth = getAuth();
const db = getFirestore();

console.log("✅ Firebase connected");

// ============================================================
// SECURITY MIDDLEWARE
// ============================================================

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  express.json({
    limit: "20kb"
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit: "20kb"
  })
);

// General rate limiter
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      success: false,
      error: "Too many requests. Please try again later."
    }
  })
);

// ============================================================
// HELPERS
// ============================================================

function clean(value, maxLength = 200) {
  if (value === undefined || value === null) {
    return "";
  }

  return String(value)
    .trim()
    .slice(0, maxLength);
}

function normalizeEmail(email) {
  return clean(email, 200).toLowerCase();
}

function dayKey(date = new Date()) {
  return date.toISOString().slice(0, 10);
}

function safeDate(value) {
  if (!value) return null;

  if (typeof value.toDate === "function") {
    return value.toDate();
  }

  if (value instanceof Date) {
    return value;
  }

  return new Date(value);
}

function generateNonce() {
  return crypto.randomBytes(24).toString("hex");
}

function base64UrlEncode(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  value = value.replace(/-/g, "+").replace(/_/g, "/");

  while (value.length % 4) {
    value += "=";
  }

  return Buffer.from(value, "base64").toString("utf8");
}

function signPayload(payload) {
  return crypto
    .createHmac("sha256", QR_SECRET)
    .update(payload)
    .digest("base64url");
}

function safeEqual(a, b) {
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);

  if (aBuffer.length !== bBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    aBuffer,
    bBuffer
  );
}

// ============================================================
// QR FUNCTIONS
// ============================================================

function createQRToken({
  uid,
  studentId
}) {
  const now = Math.floor(Date.now() / 1000);

  const payload = {
    v: 1,
    uid,
    studentId,
    iat: now,
    exp: now + QR_TTL,
    nonce: generateNonce()
  };

  const encodedPayload = base64UrlEncode(
    JSON.stringify(payload)
  );

  const signature = signPayload(
    encodedPayload
  );

  return `${encodedPayload}.${signature}`;
}

function verifyQRToken(token) {
  if (
    typeof token !== "string" ||
    token.length > 5000
  ) {
    throw new Error("Invalid QR token.");
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    throw new Error("Invalid QR format.");
  }

  const [
    encodedPayload,
    signature
  ] = parts;

  const expectedSignature =
    signPayload(encodedPayload);

  if (
    !safeEqual(
      signature,
      expectedSignature
    )
  ) {
    throw new Error("Invalid QR signature.");
  }

  let payload;

  try {
    payload = JSON.parse(
      base64UrlDecode(encodedPayload)
    );
  } catch {
    throw new Error("Invalid QR payload.");
  }

  if (
    !payload ||
    payload.v !== 1 ||
    !payload.uid ||
    !payload.studentId ||
    !payload.iat ||
    !payload.exp ||
    !payload.nonce
  ) {
    throw new Error("Invalid QR data.");
  }

  const now = Math.floor(Date.now() / 1000);

  if (payload.exp <= now) {
    throw new Error("QR code expired.");
  }

  if (payload.iat > now + 5) {
    throw new Error("QR issue time is invalid.");
  }

  if (
    payload.exp - payload.iat >
    QR_TTL + 5
  ) {
    throw new Error("QR lifetime is invalid.");
  }

  return payload;
}

// ============================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================

async function authenticate(req, res, next) {
  try {
    const header =
      req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        error: "Authentication required."
      });
    }

    const token = header.substring(7).trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        error: "Invalid authentication token."
      });
    }

    const decodedToken =
      await auth.verifyIdToken(token, true);

    const uid = decodedToken.uid;

    const userRef =
      db.collection("students").doc(uid);

    const userSnap =
      await userRef.get();

    if (!userSnap.exists) {
      return res.status(403).json({
        success: false,
        error: "User profile not found."
      });
    }

    const profile = userSnap.data();

    if (
      String(profile.accountStatus || "ACTIVE")
        .toUpperCase() !== "ACTIVE"
    ) {
      return res.status(403).json({
        success: false,
        error: "Account is not active."
      });
    }

    req.user = {
      uid,
      email: decodedToken.email || profile.email || "",
      name: profile.name || "",
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

    return res.status(401).json({
      success: false,
      error: "Invalid or expired authentication."
    });
  }
}

// ============================================================
// ROLE AUTHORIZATION
// ============================================================

function requireRoles(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: "Authentication required."
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: "You are not authorized for this action."
      });
    }

    next();
  };
}

// ============================================================
// AUDIT LOG
// ============================================================

async function createAuditLog({
  action,
  actor,
  targetUid = "",
  details = {}
}) {
  try {
    await db.collection("auditLogs").add({
      action,
      actorUid: actor?.uid || "",
      actorEmail: actor?.email || "",
      actorRole: actor?.role || "",
      targetUid,
      details,
      createdAt: FieldValue.serverTimestamp()
    });
  } catch (error) {
    console.error(
      "Audit log error:",
      error.message
    );
  }
}

// ============================================================
// AUTOMATIC ID GENERATION
// ============================================================

async function generateNextId(prefix) {
  const counterRef =
    db.collection("idCounters").doc(prefix);

  return db.runTransaction(
    async transaction => {
      const counterSnap =
        await transaction.get(counterRef);

      let nextNumber = 1001;

      if (counterSnap.exists) {
        const data = counterSnap.data();

        nextNumber =
          Number(data.nextNumber) || 1001;
      } else {
        const existingSnap =
          await db
            .collection("students")
            .where(
              "studentId",
              ">=",
              `${prefix}-`
            )
            .where(
              "studentId",
              "<",
              `${prefix}.\uf8ff`
            )
            .get();

        let maxNumber = 1000;

        existingSnap.forEach(doc => {
          const id =
            doc.data().studentId || "";

          const match =
            id.match(
              new RegExp(
                `^${prefix}-(\\d+)$`
              )
            );

          if (match) {
            maxNumber = Math.max(
              maxNumber,
              Number(match[1])
            );
          }
        });

        nextNumber = maxNumber + 1;
      }

      transaction.set(
        counterRef,
        {
          nextNumber: nextNumber + 1,
          updatedAt:
            FieldValue.serverTimestamp()
        },
        {
          merge: true
        }
      );

      return `${prefix}-${nextNumber}`;
    }
  );
}

// ============================================================
// STATUS
// ============================================================

app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    status: "online"
  });
});

// ============================================================
// CURRENT USER
// ============================================================

app.get(
  "/api/me",
  authenticate,
  (req, res) => {
    res.json({
      success: true,
      user: req.user
    });
  }
);

// ============================================================
// CREATE QR
// ============================================================

const qrLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: "Too many QR requests."
  }
});

async function generateStudentQR(req, res) {
  try {
    const studentId =
      req.user.studentId;

    if (!studentId) {
      return res.status(400).json({
        success: false,
        error: "Student ID not found."
      });
    }

    const today = dayKey();

    const entriesSnapshot =
      await db
        .collection("entries")
        .where(
          "studentId",
          "==",
          studentId
        )
        .where(
          "dayKey",
          "==",
          today
        )
        .get();

    const dailyCount =
      entriesSnapshot.size;

    if (dailyCount >= DAILY_LIMIT) {
      return res.status(429).json({
        success: false,
        error:
          "Daily entry limit reached."
      });
    }

    const token =
      createQRToken({
        uid: req.user.uid,
        studentId
      });

    const payload =
      verifyQRToken(token);

    await createAuditLog({
      action: "QR_GENERATED",
      actor: req.user,
      targetUid: req.user.uid,
      details: {
        studentId
      }
    });

    res.json({
      success: true,

      qrData: token,

      token,

      issuedAt:
        new Date(
          payload.iat * 1000
        ).toISOString(),

      expiresAt:
        new Date(
          payload.exp * 1000
        ).toISOString(),

      qr: {
        token,
        issuedAt:
          new Date(
            payload.iat * 1000
          ).toISOString(),
        expiresAt:
          new Date(
            payload.exp * 1000
          ).toISOString()
      },

      dailyCount,
      dailyLimit: DAILY_LIMIT
    });

  } catch (error) {
    console.error(
      "QR generation error:",
      error
    );

    res.status(500).json({
      success: false,
      error: "Unable to generate QR."
    });
  }
}

app.get(
  "/api/qr",
  authenticate,
  requireRoles("STUDENT"),
  qrLimiter,
  generateStudentQR
);

app.post(
  "/api/qr",
  authenticate,
  requireRoles("STUDENT"),
  qrLimiter,
  generateStudentQR
);

// ============================================================
// VERIFY QR
// ============================================================

app.post(
  "/api/verify-qr",
  authenticate,
  requireRoles(
    "SECURITY",
    "ADMIN",
    "SUPER_ADMIN"
  ),
  qrLimiter,
  async (req, res) => {
    try {
      const token =
        clean(
          req.body.token ||
          req.body.qrData,
          5000
        );

      if (!token) {
        return res.status(400).json({
          success: false,
          error: "QR token is required."
        });
      }

      const payload =
        verifyQRToken(token);

      const studentRef =
        db
          .collection("students")
          .doc(payload.uid);

      const studentSnap =
        await studentRef.get();

      if (!studentSnap.exists) {
        throw new Error(
          "Student account not found."
        );
      }

      const student =
        studentSnap.data();

      if (
        String(
          student.accountStatus || "ACTIVE"
        ).toUpperCase() !== "ACTIVE"
      ) {
        throw new Error(
          "Student account is inactive."
        );
      }

      if (
        student.studentId !==
        payload.studentId
      ) {
        throw new Error(
          "Student identity mismatch."
        );
      }

      const today = dayKey();

      const result =
        await db.runTransaction(
          async transaction => {

            const nonceRef =
              db
                .collection("usedQRNonces")
                .doc(payload.nonce);

            const nonceSnap =
              await transaction.get(
                nonceRef
              );

            if (nonceSnap.exists) {
              throw new Error(
                "QR code has already been used."
              );
            }

            const entriesQuery =
              await db
                .collection("entries")
                .where(
                  "studentId",
                  "==",
                  payload.studentId
                )
                .where(
                  "dayKey",
                  "==",
                  today
                )
                .get();

            if (
              entriesQuery.size >=
              DAILY_LIMIT
            ) {
              throw new Error(
                "Daily entry limit reached."
              );
            }

            const entryRef =
              db.collection("entries").doc();

            transaction.set(
              nonceRef,
              {
                uid: payload.uid,
                studentId:
                  payload.studentId,
                usedAt:
                  FieldValue.serverTimestamp(),
                verifiedBy:
                  req.user.uid
              }
            );

            transaction.set(
              entryRef,
              {
                studentUid:
                  payload.uid,

                studentId:
                  payload.studentId,

                studentName:
                  student.name || "",

                studentEmail:
                  student.email || "",

                studentType:
                  student.studentType || "",

                verifierUid:
                  req.user.uid,

                verifierName:
                  req.user.name || "",

                verifierRole:
                  req.user.role,

                dayKey: today,

                status: "ALLOWED",

                qrNonce:
                  payload.nonce,

                createdAt:
                  FieldValue.serverTimestamp()
              }
            );

            return entryRef.id;
          }
        );

      await createAuditLog({
        action: "ENTRY_ALLOWED",
        actor: req.user,
        targetUid: payload.uid,
        details: {
          studentId:
            payload.studentId,
          entryId: result
        }
      });

      res.json({
        success: true,
        status: "ALLOWED",
        message:
          "Entry verified successfully.",
        student: {
          uid: payload.uid,
          studentId:
            payload.studentId,
          name:
            student.name || "",
          email:
            student.email || "",
          studentType:
            student.studentType || ""
        },
        entryId: result
      });

    } catch (error) {
      console.error(
        "QR verification error:",
        error.message
      );

      res.status(400).json({
        success: false,
        status: "REJECTED",
        error:
          error.message ||
          "QR verification failed."
      });
    }
  }
);

// ============================================================
// STUDENT ENTRY HISTORY
// ============================================================

app.get(
  "/api/entries/:studentId",
  authenticate,
  async (req, res) => {
    try {
      const requestedId =
        clean(
          req.params.studentId,
          100
        );

      const isStaff =
        [
          "SECURITY",
          "ADMIN",
          "SUPER_ADMIN"
        ].includes(
          req.user.role
        );

      if (
        !isStaff &&
        requestedId !==
        req.user.studentId
      ) {
        return res.status(403).json({
          success: false,
          error:
            "You can only view your own history."
        });
      }

      const snapshot =
        await db
          .collection("entries")
          .where(
            "studentId",
            "==",
            requestedId
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
                safeDate(a.createdAt)?.getTime() ||
                0;

              const bTime =
                safeDate(b.createdAt)?.getTime() ||
                0;

              return bTime - aTime;
            }
          )
          .slice(0, 200);

      res.json({
        success: true,
        entries
      });

    } catch (error) {
      console.error(
        "History error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error:
          "Unable to load entry history."
      });
    }
  }
);

// ============================================================
// ADMIN - ALL ENTRIES
// ============================================================

app.get(
  "/api/admin/entries",
  authenticate,
  requireRoles(
    "ADMIN",
    "SUPER_ADMIN"
  ),
  async (req, res) => {
    try {
      const snapshot =
        await db
          .collection("entries")
          .orderBy(
            "createdAt",
            "desc"
          )
          .limit(500)
          .get();

      const entries =
        snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));

      res.json({
        success: true,
        entries
      });

    } catch (error) {
      console.error(
        "Admin entries error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error:
          "Unable to load entries."
      });
    }
  }
);

// ============================================================
// SUPER ADMIN - CREATE USER
// ============================================================

app.post(
  "/api/super-admin/create-user",
  authenticate,
  requireRoles("SUPER_ADMIN"),
  async (req, res) => {

    let createdAuthUser = null;

    try {
      const name =
        clean(req.body.name, 100);

      const email =
        normalizeEmail(
          req.body.email
        );

      const password =
        String(
          req.body.password || ""
        );

      const role =
        clean(
          req.body.role,
          50
        ).toUpperCase();

      const studentType =
        clean(
          req.body.studentType,
          50
        );

      const allowedRoles = [
        "STUDENT",
        "SECURITY",
        "ADMIN",
        "SUPER_ADMIN"
      ];

      if (!name) {
        return res.status(400).json({
          success: false,
          error: "Name is required."
        });
      }

      if (
        !email ||
        !email.includes("@")
      ) {
        return res.status(400).json({
          success: false,
          error: "Valid email is required."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          success: false,
          error:
            "Password must contain at least 8 characters."
        });
      }

      if (!allowedRoles.includes(role)) {
        return res.status(400).json({
          success: false,
          error: "Invalid role."
        });
      }

      let prefix;

      if (role === "STUDENT") {
        prefix = "SRMAP-STU";
      } else if (role === "SECURITY") {
        prefix = "SRMAP-SEC";
      } else if (role === "ADMIN") {
        prefix = "SRMAP-ADM";
      } else {
        prefix = "SRMAP-SADM";
      }

      const generatedId =
        await generateNextId(prefix);

      createdAuthUser =
        await auth.createUser({
          email,
          password,
          displayName: name,
          disabled: false
        });

      await db
        .collection("students")
        .doc(createdAuthUser.uid)
        .set({
          uid:
            createdAuthUser.uid,

          name,

          email,

          studentId:
            generatedId,

          studentType:
            role === "STUDENT"
              ? studentType
              : "",

          role,

          accountStatus:
            "ACTIVE",

          createdAt:
            FieldValue.serverTimestamp(),

          createdBy:
            req.user.uid
        });

      await createAuditLog({
        action: "USER_CREATED",
        actor: req.user,
        targetUid:
          createdAuthUser.uid,
        details: {
          name,
          email,
          studentId:
            generatedId,
          role
        }
      });

      res.status(201).json({
        success: true,
        message:
          "User created successfully.",
        user: {
          uid:
            createdAuthUser.uid,
          name,
          email,
          studentId:
            generatedId,
          role,
          accountStatus:
            "ACTIVE"
        }
      });

    } catch (error) {

      if (createdAuthUser) {
        try {
          await auth.deleteUser(
            createdAuthUser.uid
          );
        } catch (rollbackError) {
          console.error(
            "Auth rollback failed:",
            rollbackError.message
          );
        }
      }

      console.error(
        "Create user error:",
        error.message
      );

      res.status(400).json({
        success: false,
        error:
          error.message ||
          "Unable to create user."
      });
    }
  }
);

// ============================================================
// CREATE STUDENT
// ============================================================

app.post(
  "/api/students",
  authenticate,
  requireRoles(
    "ADMIN",
    "SUPER_ADMIN"
  ),
  async (req, res) => {

    let createdAuthUser = null;

    try {
      const name =
        clean(req.body.name, 100);

      const email =
        normalizeEmail(
          req.body.email
        );

      const password =
        String(
          req.body.password || ""
        );

      const studentType =
        clean(
          req.body.studentType,
          50
        );

      if (!name || !email) {
        return res.status(400).json({
          success: false,
          error:
            "Name and email are required."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          success: false,
          error:
            "Password must contain at least 8 characters."
        });
      }

      const studentId =
        await generateNextId(
          "SRMAP-STU"
        );

      createdAuthUser =
        await auth.createUser({
          email,
          password,
          displayName: name
        });

      await db
        .collection("students")
        .doc(createdAuthUser.uid)
        .set({
          uid:
            createdAuthUser.uid,
          name,
          email,
          studentId,
          studentType,
          role: "STUDENT",
          accountStatus:
            "ACTIVE",
          createdAt:
            FieldValue.serverTimestamp(),
          createdBy:
            req.user.uid
        });

      await createAuditLog({
        action: "STUDENT_CREATED",
        actor: req.user,
        targetUid:
          createdAuthUser.uid,
        details: {
          studentId
        }
      });

      res.status(201).json({
        success: true,
        user: {
          uid:
            createdAuthUser.uid,
          name,
          email,
          studentId,
          role: "STUDENT",
          accountStatus:
            "ACTIVE"
        }
      });

    } catch (error) {

      if (createdAuthUser) {
        try {
          await auth.deleteUser(
            createdAuthUser.uid
          );
        } catch {}
      }

      res.status(400).json({
        success: false,
        error:
          error.message ||
          "Unable to create student."
      });
    }
  }
);

// ============================================================
// CREATE ADMIN / SECURITY
// ============================================================

app.post(
  "/api/admins",
  authenticate,
  requireRoles(
    "ADMIN",
    "SUPER_ADMIN"
  ),
  async (req, res) => {

    let createdAuthUser = null;

    try {
      const name =
        clean(req.body.name, 100);

      const email =
        normalizeEmail(
          req.body.email
        );

      const password =
        String(
          req.body.password || ""
        );

      const role =
        clean(
          req.body.role,
          50
        ).toUpperCase();

      if (
        ![
          "SECURITY",
          "ADMIN"
        ].includes(role)
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Only SECURITY or ADMIN can be created here."
        });
      }

      if (!name || !email) {
        return res.status(400).json({
          success: false,
          error:
            "Name and email are required."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          success: false,
          error:
            "Password must contain at least 8 characters."
        });
      }

      const prefix =
        role === "SECURITY"
          ? "SRMAP-SEC"
          : "SRMAP-ADM";

      const generatedId =
        await generateNextId(prefix);

      createdAuthUser =
        await auth.createUser({
          email,
          password,
          displayName: name
        });

      await db
        .collection("students")
        .doc(createdAuthUser.uid)
        .set({
          uid:
            createdAuthUser.uid,
          name,
          email,
          studentId:
            generatedId,
          studentType: "",
          role,
          accountStatus:
            "ACTIVE",
          createdAt:
            FieldValue.serverTimestamp(),
          createdBy:
            req.user.uid
        });

      await createAuditLog({
        action: "STAFF_CREATED",
        actor: req.user,
        targetUid:
          createdAuthUser.uid,
        details: {
          studentId:
            generatedId,
          role
        }
      });

      res.status(201).json({
        success: true,
        user: {
          uid:
            createdAuthUser.uid,
          name,
          email,
          studentId:
            generatedId,
          role,
          accountStatus:
            "ACTIVE"
        }
      });

    } catch (error) {

      if (createdAuthUser) {
        try {
          await auth.deleteUser(
            createdAuthUser.uid
          );
        } catch {}
      }

      res.status(400).json({
        success: false,
        error:
          error.message ||
          "Unable to create staff."
      });
    }
  }
);

// ============================================================
// ADMIN - ALL USERS
// ============================================================

app.get(
  "/api/admin/users",
  authenticate,
  requireRoles(
    "ADMIN",
    "SUPER_ADMIN"
  ),
  async (req, res) => {
    try {
      const snapshot =
        await db
          .collection("students")
          .get();

      const users =
        snapshot.docs.map(doc => ({
          uid: doc.id,
          ...doc.data()
        }));

      res.json({
        success: true,
        users
      });

    } catch (error) {
      console.error(
        "Users error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error:
          "Unable to load users."
      });
    }
  }
);

// ============================================================
// ADMIN - STAFF
// ============================================================

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
          .collection("students")
          .get();

      const staff =
        snapshot.docs
          .map(doc => ({
            uid: doc.id,
            ...doc.data()
          }))
          .filter(user =>
            [
              "SECURITY",
              "ADMIN",
              "SUPER_ADMIN"
            ].includes(user.role)
          );

      res.json({
        success: true,
        staff
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error:
          "Unable to load staff."
      });
    }
  }
);

// ============================================================
// BLOCK / UNBLOCK USER
// ============================================================

app.post(
  "/api/users/:uid/status",
  authenticate,
  requireRoles(
    "ADMIN",
    "SUPER_ADMIN"
  ),
  async (req, res) => {
    try {
      const targetUid =
        clean(
          req.params.uid,
          200
        );

      // Supports both names so old frontend
      // and new frontend can work.
      const status =
        clean(
          req.body.status ||
          req.body.accountStatus,
          50
        ).toUpperCase();

      if (
        ![
          "ACTIVE",
          "BLOCKED"
        ].includes(status)
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Status must be ACTIVE or BLOCKED."
        });
      }

      if (
        targetUid ===
        req.user.uid
      ) {
        return res.status(400).json({
          success: false,
          error:
            "You cannot change your own account status."
        });
      }

      const targetRef =
        db
          .collection("students")
          .doc(targetUid);

      const targetSnap =
        await targetRef.get();

      if (!targetSnap.exists) {
        return res.status(404).json({
          success: false,
          error:
            "User not found."
        });
      }

      const targetUser =
        targetSnap.data();

      if (
        targetUser.role ===
        "SUPER_ADMIN" &&
        req.user.role !==
        "SUPER_ADMIN"
      ) {
        return res.status(403).json({
          success: false,
          error:
            "Only Super Admin can modify Super Admin accounts."
        });
      }

      await targetRef.update({
        accountStatus: status,
        updatedAt:
          FieldValue.serverTimestamp(),
        updatedBy:
          req.user.uid
      });

      await auth.updateUser(
        targetUid,
        {
          disabled:
            status === "BLOCKED"
        }
      );

      await createAuditLog({
        action:
          status === "BLOCKED"
            ? "USER_BLOCKED"
            : "USER_UNBLOCKED",
        actor: req.user,
        targetUid,
        details: {
          status
        }
      });

      res.json({
        success: true,
        message:
          `User ${status.toLowerCase()} successfully.`,
        accountStatus:
          status
      });

    } catch (error) {
      console.error(
        "Status update error:",
        error.message
      );

      res.status(400).json({
        success: false,
        error:
          error.message ||
          "Unable to update user status."
      });
    }
  }
);

// ============================================================
// AUDIT LOGS
// ============================================================

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
          .collection("auditLogs")
          .orderBy(
            "createdAt",
            "desc"
          )
          .limit(500)
          .get();

      const logs =
        snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));

      res.json({
        success: true,
        logs
      });

    } catch (error) {
      console.error(
        "Audit logs error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error:
          "Unable to load audit logs."
      });
    }
  }
);

// ============================================================
// LOGOUT
// ============================================================

app.post(
  "/api/logout",
  authenticate,
  async (req, res) => {
    try {
      await createAuditLog({
        action: "LOGOUT",
        actor: req.user,
        targetUid:
          req.user.uid
      });

      res.json({
        success: true,
        message:
          "Logout recorded successfully."
      });

    } catch (error) {
      res.json({
        success: true
      });
    }
  }
);

// ============================================================
// STATIC WEBSITE
// ============================================================

app.use(
  express.static(
    __dirname,
    {
      extensions: ["html"]
    }
  )
);

// ============================================================
// 404 API HANDLER
// ============================================================

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      success: false,
      error: "API endpoint not found."
    });
  }
);

// ============================================================
// GENERAL ERROR HANDLER
// ============================================================

app.use(
  (error, req, res, next) => {
    console.error(
      "Server error:",
      error
    );

    res.status(500).json({
      success: false,
      error:
        "Internal server error."
    });
  }
);

// ============================================================
// START SERVER
// ============================================================

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log("");
    console.log(
      "========================================"
    );
    console.log(
      " SRM AP DAYPASS SERVER"
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
      "👥 Role management enabled"
    );
    console.log(
      "📝 Audit logging enabled"
    );
    console.log(
      "========================================"
    );
    console.log("");
  }
);