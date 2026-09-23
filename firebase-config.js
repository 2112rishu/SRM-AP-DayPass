// ============================================================
// SRM AP DAYPASS - FIREBASE WEB CONFIG
// ============================================================

const firebaseConfig = {
    apiKey: "AIzaSyCu8XDAIBqIVp_49ta4383TP4xdP-n2sbw",
    authDomain: "srm-ap-daypass.firebaseapp.com",
    databaseURL: "https://srm-ap-daypass-default-rtdb.firebaseio.com",
    projectId: "srm-ap-daypass",
    storageBucket: "srm-ap-daypass.firebasestorage.app",
    messagingSenderId: "40857485563",
    appId: "1:40857485563:web:0f4dd9058d3cf451b8705e",
    measurementId: "G-WDYKW0TBFE"
};


// ============================================================
// INITIALIZE FIREBASE
// ============================================================

if (!firebase.apps.length) {
    firebase.initializeApp(firebaseConfig);
}

const auth = firebase.auth();
const db = firebase.firestore();


// ============================================================
// CHECK FIREBASE CONFIG
// ============================================================

function showConfigWarning() {

    const bad =
        !firebaseConfig.apiKey ||
        firebaseConfig.apiKey.includes("PASTE_") ||
        !firebaseConfig.messagingSenderId ||
        firebaseConfig.messagingSenderId.includes("PASTE_") ||
        !firebaseConfig.appId ||
        firebaseConfig.appId.includes("PASTE_");

    if (bad) {
        console.warn(
            "Firebase Web config is still using placeholders. " +
            "Replace the values in firebase-config.js."
        );
    }
}

showConfigWarning();


// ============================================================
// GET FIREBASE ID TOKEN
// ============================================================

async function getIdToken() {

    const user = auth.currentUser;

    if (!user) {
        throw new Error("Please login first.");
    }

    return await user.getIdToken(true);
}


// ============================================================
// API REQUEST HELPER
// ============================================================

async function apiRequest(url, options = {}) {

    const token = await getIdToken();

    const headers = {
        "Authorization": `Bearer ${token}`,

        ...(options.body
            ? { "Content-Type": "application/json" }
            : {}),

        ...(options.headers || {})
    };

    const response = await fetch(url, {
        ...options,
        headers
    });

    const text = await response.text();

    let data = {};

    if (text.trim()) {

        try {
            data = JSON.parse(text);
        }

        catch {
            throw new Error(
                "Server returned invalid JSON."
            );
        }
    }

    if (!response.ok) {

        throw new Error(
            data.message ||
            data.error ||
            `Server error: ${response.status}`
        );
    }

    return data;
}


// ============================================================
// HTML ESCAPE HELPER
// ============================================================

function escapeHtml(value) {

    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


// ============================================================
// DATE/TIME FORMATTER
// ============================================================

function formatDateTime(value) {

    if (!value) {
        return "-";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString("en-IN", {
        dateStyle: "medium",
        timeStyle: "short"
    });
}


// ============================================================
// REQUIRE LOGIN
// ============================================================

async function requireLoggedIn() {

    return new Promise((resolve, reject) => {

        const unsubscribe =
            auth.onAuthStateChanged(user => {

                unsubscribe();

                if (user) {

                    resolve(user);

                } else {

                    window.location.href =
                        "index.html";

                    reject(
                        new Error("Not logged in.")
                    );
                }
            });
    });
}


// ============================================================
// GET CURRENT USER PROFILE
// ============================================================

async function getMyProfile() {

    return await apiRequest("/api/me");
}


// ============================================================
// REQUIRE SPECIFIC ROLE
// ============================================================

async function requireRole(role) {

    await requireLoggedIn();

    try {

        const data = await getMyProfile();

        const profile =
            data.profile || data.user;

        if (!profile) {

            throw new Error(
                "User profile not found."
            );
        }

        if (profile.role !== role) {

            window.location.href =
                role === "admin"
                    ? "dashboard.html"
                    : "admin.html";

            throw new Error(
                "Access denied."
            );
        }

        if (
            profile.accountStatus ===
            "BLOCKED"
        ) {

            await auth.signOut();

            window.location.href =
                "student-login.html";

            throw new Error(
                "Account blocked."
            );
        }

        return data;

    }

    catch (error) {

        console.error(
            "Role verification error:",
            error
        );

        throw error;
    }
}


// ============================================================
// LOGOUT
// ============================================================

async function logout() {

    try {

        await auth.signOut();

        window.location.href =
            "index.html";

    }

    catch (error) {

        console.error(
            "Logout error:",
            error
        );

        alert(
            "Unable to logout. Please try again."
        );
    }
}