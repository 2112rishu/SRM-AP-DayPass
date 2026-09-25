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


/* =========================================================
   SECURITY CHECK
========================================================= */

if (!QR_SECRET || QR_SECRET.length < 48) {
    console.error(
        "DAYPASS_QR_SECRET is missing or shorter than 48 characters."
    );

    process.exit(1);
}


/* =========================================================
   FIREBASE INITIALIZATION
========================================================= */

function initializeFirebase() {

    try {

        return admin.app();

    } catch (_) {

        // Firebase has not been initialized yet.

    }

    let serviceAccount;


    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {

        try {

            serviceAccount = JSON.parse(
                process.env.FIREBASE_SERVICE_ACCOUNT_JSON
            );

        } catch (error) {

            console.error(
                "Invalid FIREBASE_SERVICE_ACCOUNT_JSON."
            );

            process.exit(1);

        }

    } else {

        const serviceAccountFile = path.join(
            __dirname,
            "firebase-service-account.json"
        );


        if (!fs.existsSync(serviceAccountFile)) {

            console.error(
                "firebase-service-account.json was not found."
            );

            process.exit(1);

        }


        try {

            serviceAccount = JSON.parse(
                fs.readFileSync(
                    serviceAccountFile,
                    "utf8"
                )
            );

        } catch (error) {

            console.error(
                "Unable to read firebase-service-account.json."
            );

            process.exit(1);

        }

    }


    return admin.initializeApp({

        credential:
            admin.credential.cert(serviceAccount)

    });

}


initializeFirebase();


const db = admin.firestore();

const auth = admin.auth();


console.log("Firebase connected.");



/* =========================================================
   EXPRESS SECURITY
========================================================= */

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



/* =========================================================
   RATE LIMITING
========================================================= */

const generalLimiter = rateLimit({

    windowMs: 15 * 60 * 1000,

    max: 300,

    standardHeaders: true,

    legacyHeaders: false

});


const qrLimiter = rateLimit({

    windowMs: 60 * 1000,

    max: 60,

    standardHeaders: true,

    legacyHeaders: false

});


app.use(generalLimiter);



/* =========================================================
   HELPER FUNCTIONS
========================================================= */

function clean(value, length = 500) {

    if (
        value === undefined ||
        value === null
    ) {

        return "";

    }

    return String(value)
        .trim()
        .slice(0, length);

}



function getToday() {

    return new Intl.DateTimeFormat(
        "en-CA",
        {
            timeZone: "Asia/Kolkata",

            year: "numeric",

            month: "2-digit",

            day: "2-digit"
        }
    ).format(new Date());

}



function sameConstantTime(a, b) {

    try {

        const x = Buffer.from(a);

        const y = Buffer.from(b);


        if (x.length !== y.length) {

            return false;

        }


        return crypto.timingSafeEqual(
            x,
            y
        );

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

        await db
            .collection("auditLogs")
            .add({

                actorUid,

                actorRole,

                action,

                targetUid,

                details,

                createdAt:
                    admin.firestore
                        .FieldValue
                        .serverTimestamp()

            });

    } catch (error) {

        console.error(
            "Audit error:",
            error.message
        );

    }

}



/* =========================================================
   AUTHENTICATION
========================================================= */

async function authenticate(
    req,
    res,
    next
) {

    try {

        const header =
            req.headers.authorization || "";


        if (!header.startsWith("Bearer ")) {

            return res.status(401).json({

                error:
                    "Authentication required."

            });

        }


        const token =
            header
                .substring(7)
                .trim();


        const decoded =
            await auth.verifyIdToken(
                token,
                true
            );


        const uid = decoded.uid;


        const profileSnapshot =
            await db
                .collection("students")
                .doc(uid)
                .get();


        if (!profileSnapshot.exists) {

            return res.status(403).json({

                error:
                    "User profile not found."

            });

        }


        const profile =
            profileSnapshot.data();


        const accountStatus =
            profile.accountStatus ||
            "ACTIVE";


        if (accountStatus !== "ACTIVE") {

            return res.status(403).json({

                error:
                    "This account is blocked."

            });

        }


        req.user = {

            uid,

            email:
                decoded.email ||
                profile.email ||
                "",

            name:
                profile.name ||
                decoded.name ||
                "",

            studentId:
                profile.studentId ||
                "",

            studentType:
                profile.studentType ||
                "",

            role:
                profile.role ||
                "STUDENT",

            accountStatus

        };


        next();

    } catch (error) {

        console.error(
            "Authentication error:",
            error.message
        );


        return res.status(401).json({

            error:
                "Authentication failed."

        });

    }

}



/* =========================================================
   ROLE AUTHORIZATION
========================================================= */

function requireRoles(...roles) {

    return (
        req,
        res,
        next
    ) => {

        if (
            !req.user ||
            !roles.includes(req.user.role)
        ) {

            return res.status(403).json({

                error:
                    "You are not authorized."

            });

        }


        next();

    };

}



/* =========================================================
   QR SIGNATURE
========================================================= */

function createSignature(data) {

    return crypto
        .createHmac(
            "sha256",
            QR_SECRET
        )
        .update(data)
        .digest("base64url");

}



/* =========================================================
   CREATE QR
========================================================= */

function createQR(user) {

    const now =
        Math.floor(
            Date.now() / 1000
        );


    const payload = {

        v: 1,

        uid: user.uid,

        studentId: user.studentId,

        iat: now,

        exp: now + QR_TTL,

        nonce:
            crypto
                .randomBytes(16)
                .toString("hex")

    };


    const encoded =
        Buffer
            .from(
                JSON.stringify(payload)
            )
            .toString("base64url");


    const signature =
        createSignature(encoded);


    return {

        token:
            `${encoded}.${signature}`,

        issuedAt: now,

        expiresAt:
            now + QR_TTL

    };

}



/* =========================================================
   VERIFY QR
========================================================= */

function verifyQR(token) {

    if (!token) {

        throw new Error(
            "QR code is required."
        );

    }


    const parts =
        token.split(".");


    if (parts.length !== 2) {

        throw new Error(
            "Invalid QR code."
        );

    }


    const encoded =
        parts[0];


    const signature =
        parts[1];


    const expected =
        createSignature(encoded);


    if (
        !sameConstantTime(
            signature,
            expected
        )
    ) {

        throw new Error(
            "Invalid QR signature."
        );

    }


    let payload;


    try {

        payload =
            JSON.parse(
                Buffer
                    .from(
                        encoded,
                        "base64url"
                    )
                    .toString("utf8")
            );

    } catch (_) {

        throw new Error(
            "Invalid QR data."
        );

    }


    const now =
        Math.floor(
            Date.now() / 1000
        );


    if (payload.v !== 1) {

        throw new Error(
            "Unsupported QR version."
        );

    }


    if (
        !payload.uid ||
        !payload.studentId ||
        !payload.nonce
    ) {

        throw new Error(
            "Incomplete QR code."
        );

    }


    if (payload.exp <= now) {

        throw new Error(
            "QR code has expired."
        );

    }


    if (payload.iat > now + 5) {

        throw new Error(
            "Invalid QR issue time."
        );

    }


    if (
        payload.exp -
        payload.iat >
        QR_TTL + 5
    ) {

        throw new Error(
            "Invalid QR lifetime."
        );

    }


    return payload;

}



/* =========================================================
   AUTOMATIC ID GENERATION
========================================================= */

async function generateNextId(prefix) {

    const counterRef =
        db
            .collection("idCounters")
            .doc(prefix);


    const number =
        await db.runTransaction(
            async transaction => {

                const counterSnapshot =
                    await transaction.get(
                        counterRef
                    );


                let nextNumber = 1001;


                if (
                    counterSnapshot.exists
                ) {

                    nextNumber =
                        (
                            Number(
                                counterSnapshot
                                    .data()
                                    .lastNumber
                            ) ||
                            1000
                        ) + 1;

                } else {

                    const snapshot =
                        await db
                            .collection("students")
                            .get();


                    let maxNumber = 1000;


                    const escapedPrefix =
                        prefix.replace(
                            /[.*+?^${}()|[\]\\]/g,
                            "\\$&"
                        );


                    snapshot.forEach(
                        doc => {

                            const id =
                                String(
                                    doc
                                        .data()
                                        .studentId ||
                                    ""
                                );


                            const match =
                                id.match(
                                    new RegExp(
                                        "^" +
                                        escapedPrefix +
                                        "-(\\d+)$"
                                    )
                                );


                            if (match) {

                                maxNumber =
                                    Math.max(
                                        maxNumber,
                                        Number(
                                            match[1]
                                        )
                                    );

                            }

                        }
                    );


                    nextNumber =
                        maxNumber + 1;

                }


                transaction.set(

                    counterRef,

                    {

                        prefix,

                        lastNumber:
                            nextNumber,

                        updatedAt:
                            admin.firestore
                                .FieldValue
                                .serverTimestamp()

                    },

                    {
                        merge: true
                    }

                );


                return nextNumber;

            }
        );


    return `${prefix}-${number}`;

}



/* =========================================================
   ROLE PREFIXES
========================================================= */

const ROLE_PREFIXES = {

    STUDENT:
        "SRMAP-STU",

    SECURITY:
        "SRMAP-SEC",

    ADMIN:
        "SRMAP-ADM",

    SUPER_ADMIN:
        "SRMAP-SADM"

};



/* =========================================================
   STATUS
========================================================= */

app.get(
    "/api/status",
    (req, res) => {

        res.json({

            success: true,

            status: "online",

            environment:
                process.env.NODE_ENV ||
                "development",

            time:
                new Date().toISOString()

        });

    }
);



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
   STUDENT QR GENERATION
========================================================= */

async function generateQRForStudent(
    req,
    res
) {

    try {

        if (
            req.user.role !==
            "STUDENT"
        ) {

            return res.status(403).json({

                error:
                    "Only students can generate QR codes."

            });

        }


        const snapshot =
            await db
                .collection("entries")
                .where(
                    "studentUid",
                    "==",
                    req.user.uid
                )
                .get();


        const today =
            getToday();


        let todayCount = 0;


        snapshot.forEach(
            doc => {

                if (
                    doc.data().dayKey ===
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

            return res.status(429).json({

                error:
                    "Daily entry limit reached.",

                dailyCount:
                    todayCount,

                dailyLimit:
                    DAILY_LIMIT

            });

        }


        const qr =
            createQR(req.user);


        await audit(

            req.user.uid,

            req.user.role,

            "QR_GENERATED",

            req.user.uid

        );


        res.json({

            success: true,

            qrData:
                qr.token,

            token:
                qr.token,

            issuedAt:
                qr.issuedAt,

            expiresAt:
                qr.expiresAt,

            dailyCount:
                todayCount,

            dailyLimit:
                DAILY_LIMIT

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
    generateQRForStudent
);


app.post(
    "/api/qr",
    qrLimiter,
    authenticate,
    generateQRForStudent
);



/* =========================================================
   VERIFY QR
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

            const token =
                clean(
                    req.body.qrData ||
                    req.body.token ||
                    req.body.qr,
                    10000
                );


            const payload =
                verifyQR(token);


            const studentSnapshot =
                await db
                    .collection("students")
                    .doc(payload.uid)
                    .get();


            if (
                !studentSnapshot.exists
            ) {

                throw new Error(
                    "Student account not found."
                );

            }


            const student =
                studentSnapshot.data();


            if (
                (
                    student.accountStatus ||
                    "ACTIVE"
                ) !== "ACTIVE"
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


            const today =
                getToday();


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


                        const nonceSnapshot =
                            await transaction.get(
                                nonceRef
                            );


                        if (
                            nonceSnapshot.exists
                        ) {

                            throw new Error(
                                "This QR code has already been used."
                            );

                        }


                        const entriesSnapshot =
                            await db
                                .collection("entries")
                                .where(
                                    "studentUid",
                                    "==",
                                    payload.uid
                                )
                                .get();


                        let todayCount = 0;


                        entriesSnapshot.forEach(
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
                                .collection("entries")
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

            const studentId =
                clean(
                    req.params.studentId,
                    100
                );


            if (
                req.user.role ===
                "STUDENT" &&
                studentId !==
                req.user.studentId
            ) {

                return res.status(403).json({

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
                        studentId
                    )
                    .get();


            const entries =
                snapshot.docs

                    .map(doc => ({

                        id:
                            doc.id,

                        ...doc.data()

                    }))

                    .sort(
                        (a, b) => {

                            const aTime =
                                a.createdAt &&
                                typeof a.createdAt
                                    .toMillis ===
                                    "function"
                                    ? a.createdAt
                                        .toMillis()
                                    : 0;


                            const bTime =
                                b.createdAt &&
                                typeof b.createdAt
                                    .toMillis ===
                                    "function"
                                    ? b.createdAt
                                        .toMillis()
                                    : 0;


                            return bTime - aTime;

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
   STAFF ENTRY HISTORY
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

            const snapshot =
                await db
                    .collection("entries")
                    .limit(200)
                    .get();


            const entries =
                snapshot.docs

                    .map(doc => ({

                        id:
                            doc.id,

                        ...doc.data()

                    }))

                    .sort(
                        (a, b) => {

                            const aTime =
                                a.createdAt &&
                                typeof a.createdAt
                                    .toMillis ===
                                    "function"
                                    ? a.createdAt
                                        .toMillis()
                                    : 0;


                            const bTime =
                                b.createdAt &&
                                typeof b.createdAt
                                    .toMillis ===
                                    "function"
                                    ? b.createdAt
                                        .toMillis()
                                    : 0;


                            return bTime - aTime;

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
   SUPER ADMIN - CREATE ANY USER
========================================================= */

app.post(

    "/api/super-admin/create-user",

    authenticate,

    requireRoles("SUPER_ADMIN"),

    async (req, res) => {

        let createdAuthUser = null;


        try {

            const name =
                clean(
                    req.body.name,
                    200
                );


            const email =
                clean(
                    req.body.email,
                    200
                );


            const password =
                String(
                    req.body.password ||
                    ""
                );


            const role =
                clean(
                    req.body.role,
                    50
                ).toUpperCase();


            const studentType =
                clean(
                    req.body.studentType,
                    100
                );


            const allowedRoles = [

                "STUDENT",

                "SECURITY",

                "ADMIN",

                "SUPER_ADMIN"

            ];


            if (
                !allowedRoles.includes(role)
            ) {

                return res.status(400).json({

                    error:
                        "Invalid account type."

                });

            }


            if (
                !name ||
                !email ||
                !password
            ) {

                return res.status(400).json({

                    error:
                        "Name, email and password are required."

                });

            }


            if (
                password.length < 8
            ) {

                return res.status(400).json({

                    error:
                        "Password must be at least 8 characters."

                });

            }


            const prefix =
                ROLE_PREFIXES[role];


            const generatedId =
                await generateNextId(
                    prefix
                );


            createdAuthUser =
                await auth.createUser({

                    email,

                    password,

                    displayName:
                        name

                });


            const profile = {

                uid:
                    createdAuthUser.uid,

                name,

                email,

                studentId:
                    generatedId,

                role,

                accountStatus:
                    "ACTIVE",

                createdAt:
                    admin.firestore
                        .FieldValue
                        .serverTimestamp(),

                createdBy:
                    req.user.uid

            };


            if (
                role === "STUDENT"
            ) {

                profile.studentType =
                    studentType ||
                    "Day Scholar";

            } else {

                profile.studentType =
                    "STAFF";

            }


            try {

                await db
                    .collection("students")
                    .doc(
                        createdAuthUser.uid
                    )
                    .set(profile);

            } catch (firestoreError) {

                await auth.deleteUser(
                    createdAuthUser.uid
                );

                createdAuthUser = null;

                throw firestoreError;

            }


            await audit(

                req.user.uid,

                req.user.role,

                "USER_CREATED",

                createdAuthUser.uid,

                {

                    name,

                    email,

                    role,

                    studentId:
                        generatedId

                }

            );


            return res.status(201).json({

                success: true,

                message:
                    `${role} account created successfully.`,

                user: {

                    uid:
                        createdAuthUser.uid,

                    name,

                    email,

                    role,

                    studentId:
                        generatedId,

                    accountStatus:
                        "ACTIVE"

                }

            });

        } catch (error) {

            console.error(
                "Super Admin create user error:",
                error
            );


            if (
                error.code ===
                "auth/email-already-exists"
            ) {

                return res.status(409).json({

                    error:
                        "An account with this email already exists."

                });

            }


            return res.status(500).json({

                error:
                    "Unable to create user."

            });

        }

    }

);



/* =========================================================
   ADMIN - CREATE STUDENT
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

            const email =
                clean(
                    req.body.email,
                    200
                );


            const password =
                String(
                    req.body.password ||
                    ""
                );


            const name =
                clean(
                    req.body.name,
                    200
                );


            const studentType =
                clean(
                    req.body.studentType,
                    100
                );


            if (
                !email ||
                !name ||
                password.length < 8
            ) {

                return res.status(400).json({

                    error:
                        "Valid email, password and name are required."

                });

            }


            const studentId =
                await generateNextId(
                    ROLE_PREFIXES.STUDENT
                );


            const user =
                await auth.createUser({

                    email,

                    password,

                    displayName:
                        name

                });


            try {

                await db
                    .collection("students")
                    .doc(user.uid)
                    .set({

                        uid:
                            user.uid,

                        email,

                        studentId,

                        name,

                        studentType:
                            studentType ||
                            "Day Scholar",

                        role:
                            "STUDENT",

                        accountStatus:
                            "ACTIVE",

                        createdAt:
                            admin.firestore
                                .FieldValue
                                .serverTimestamp()

                    });

            } catch (firestoreError) {

                await auth.deleteUser(
                    user.uid
                );

                throw firestoreError;

            }


            await audit(

                req.user.uid,

                req.user.role,

                "STUDENT_CREATED",

                user.uid,

                {

                    studentId

                }

            );


            res.status(201).json({

                success: true,

                message:
                    "Student created successfully.",

                uid:
                    user.uid,

                studentId

            });

        } catch (error) {

            console.error(
                "Create student error:",
                error
            );


            if (
                error.code ===
                "auth/email-already-exists"
            ) {

                return res.status(409).json({

                    error:
                        "An account with this email already exists."

                });

            }


            res.status(400).json({

                error:
                    error.message ||
                    "Could not create student."

            });

        }

    }

);



/* =========================================================
   ADMIN - CREATE STAFF
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

            const email =
                clean(
                    req.body.email,
                    200
                );


            const password =
                String(
                    req.body.password ||
                    ""
                );


            const name =
                clean(
                    req.body.name,
                    200
                );


            const role =
                clean(
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
                role ===
                    "SUPER_ADMIN"
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


            const prefix =
                ROLE_PREFIXES[role];


            const staffId =
                await generateNextId(
                    prefix
                );


            const user =
                await auth.createUser({

                    email,

                    password,

                    displayName:
                        name

                });


            try {

                await db
                    .collection("students")
                    .doc(user.uid)
                    .set({

                        uid:
                            user.uid,

                        email,

                        name,

                        studentId:
                            staffId,

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

            } catch (firestoreError) {

                await auth.deleteUser(
                    user.uid
                );

                throw firestoreError;

            }


            await audit(

                req.user.uid,

                req.user.role,

                "STAFF_CREATED",

                user.uid,

                {

                    role,

                    studentId:
                        staffId

                }

            );


            res.status(201).json({

                success: true,

                message:
                    "Staff account created.",

                uid:
                    user.uid,

                studentId:
                    staffId,

                role

            });

        } catch (error) {

            console.error(
                "Create staff error:",
                error
            );


            if (
                error.code ===
                "auth/email-already-exists"
            ) {

                return res.status(409).json({

                    error:
                        "An account with this email already exists."

                });

            }


            res.status(400).json({

                error:
                    error.message ||
                    "Could not create staff."

            });

        }

    }

);



/* =========================================================
   ALL USERS
========================================================= */

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
                snapshot.docs

                    .map(doc => ({

                        uid:
                            doc.id,

                        ...doc.data()

                    }))

                    .sort(
                        (a, b) =>
                            String(
                                a.name || ""
                            ).localeCompare(
                                String(
                                    b.name || ""
                                )
                            )
                    );


            res.json({

                success: true,

                users

            });

        } catch (error) {

            console.error(
                "Users list error:",
                error
            );


            res.status(500).json({

                error:
                    "Unable to load users."

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
                    .collection("students")
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

                        uid:
                            doc.id,

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

            const uid =
                clean(
                    req.params.uid,
                    200
                );


            const status =
                clean(
                    req.body.status,
                    50
                ).toUpperCase();


            if (
                uid ===
                req.user.uid
            ) {

                return res.status(403).json({

                    error:
                        "You cannot change your own account status."

                });

            }


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


            const ref =
                db
                    .collection("students")
                    .doc(uid);


            const snapshot =
                await ref.get();


            if (!snapshot.exists) {

                return res.status(404).json({

                    error:
                        "User not found."

                });

            }


            const target =
                snapshot.data();


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


            await auth.updateUser(

                uid,

                {

                    disabled:
                        status ===
                        "BLOCKED"

                }

            );


            await audit(

                req.user.uid,

                req.user.role,

                status ===
                    "BLOCKED"
                    ? "USER_BLOCKED"
                    : "USER_UNBLOCKED",

                uid

            );


            res.json({

                success: true,

                message:
                    status ===
                    "BLOCKED"
                        ? "User blocked."
                        : "User unblocked."

            });

        } catch (error) {

            console.error(
                "Status update error:",
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
                    .collection("auditLogs")
                    .limit(100)
                    .get();


            const logs =
                snapshot.docs

                    .map(doc => ({

                        id:
                            doc.id,

                        ...doc.data()

                    }))

                    .sort(
                        (a, b) => {

                            const aTime =
                                a.createdAt &&
                                typeof a.createdAt
                                    .toMillis ===
                                    "function"
                                    ? a.createdAt
                                        .toMillis()
                                    : 0;


                            const bTime =
                                b.createdAt &&
                                typeof b.createdAt
                                    .toMillis ===
                                    "function"
                                    ? b.createdAt
                                        .toMillis()
                                    : 0;


                            return bTime - aTime;

                        }
                    );


            res.json({

                success: true,

                logs

            });

        } catch (error) {

            console.error(
                "Audit logs error:",
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
   STATIC WEBSITE
========================================================= */

app.use(

    express.static(
        __dirname,
        {
            extensions: ["html"]
        }
    )

);



/* =========================================================
   API 404
========================================================= */

app.use(
    "/api",
    (req, res) => {

        res.status(404).json({

            error:
                "API endpoint not found."

        });

    }
);



/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "Global error:",
            error
        );


        if (
            res.headersSent
        ) {

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

const server =
    app.listen(

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
                `Server running on port ${PORT}`
            );

            console.log(
                `http://localhost:${PORT}`
            );

            console.log(
                "Firebase authentication enabled"
            );

            console.log(
                "Student QR enabled"
            );

            console.log(
                "Security verification enabled"
            );

            console.log(
                "Entry history enabled"
            );

            console.log(
                "Automatic ID generation enabled"
            );

            console.log(
                "Super Admin management enabled"
            );

            console.log(
                "========================================"
            );

            console.log("");

        }

    );



/* =========================================================
   SERVER ERROR
========================================================= */

server.on(
    "error",
    error => {

        console.error(
            "Server error:",
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



/* =========================================================
   SHUTDOWN
========================================================= */

process.on(
    "SIGINT",
    () => {

        console.log(
            "Shutting down server..."
        );


        server.close(
            () =>
                process.exit(0)
        );

    }
);


process.on(
    "SIGTERM",
    () => {

        server.close(
            () =>
                process.exit(0)
        );

    }
);