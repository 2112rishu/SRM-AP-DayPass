// ============================================================
// SRM AP DAYPASS - FIREBASE WEB CONFIG
// Replace ONLY the values below with your Firebase Web App config.
// Do NOT put your Firebase service-account JSON in this file.
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
if (!firebase.apps.length) {
    firebase.initializeApp(firebaseConfig);
}

const auth = firebase.auth();
const db = firebase.firestore();

function showConfigWarning() {
    const bad =
        !firebaseConfig.apiKey ||
        firebaseConfig.apiKey.includes("PASTE_") ||
        !firebaseConfig.messagingSenderId ||
        firebaseConfig.messagingSenderId.includes("PASTE_") ||
        !firebaseConfig.appId ||
        firebaseConfig.appId.includes("PASTE_");

    if (bad) {
        console.warn("Firebase Web config is still using placeholders. Replace the values in firebase-config.js.");
    }
}

showConfigWarning();

async function getIdToken() {
    const user = auth.currentUser;
    if (!user) {
        throw new Error("Please login first.");
    }
    return await user.getIdToken(true);
}

async function apiRequest(url, options = {}) {
    const token = await getIdToken();

    const headers = {
        "Authorization": `Bearer ${token}`,
        ...(options.body ? { "Content-Type": "application/json" } : {}),
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
        } catch {
            throw new Error("Server returned invalid JSON.");
        }
    }

    if (!response.ok) {
        throw new Error(data.error || `Server error: ${response.status}`);
    }

    return data;
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function formatDateTime(value) {
    if (!value) return "-";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString("en-IN", {
        dateStyle: "medium",
        timeStyle: "short"
    });
}

async function requireLoggedIn() {
    return new Promise((resolve, reject) => {
        const unsubscribe = auth.onAuthStateChanged(user => {
            unsubscribe();
            if (user) resolve(user);
            else {
                window.location.href = "index.html";
                reject(new Error("Not logged in."));
            }
        });
    });
}

async function getMyProfile() {
    return await apiRequest("/api/me");
}

async function requireRole(role) {
    await requireLoggedIn();

    try {
        const data = await getMyProfile();

        if (data.profile.role !== role) {
            window.location.href = role === "admin"
                ? "dashboard.html"
                : "admin.html";
            throw new Error("Access denied.");
        }

        if (data.profile.accountStatus === "BLOCKED") {
            await auth.signOut();
            window.location.href = "student-login.html";
            throw new Error("Account blocked.");
        }

        return data;
    } catch (error) {
        console.error(error);
        throw error;
    }
}

async function logout() {
    await auth.signOut();
    window.location.href = "index.html";
}
