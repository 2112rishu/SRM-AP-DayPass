"use strict";

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

async function getIdToken() {
    const user = auth.currentUser;

    if (!user) {
        throw new Error("Authentication required.");
    }

    return await user.getIdToken(true);
}

async function apiRequest(url, options = {}) {
    const token = await getIdToken();

    const headers = {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
        ...(options.headers || {})
    };

    const response = await fetch(url, {
        ...options,
        headers
    });

    const data = await response.json().catch(() => ({
        error: "Invalid server response."
    }));

    if (!response.ok) {
        throw new Error(data.error || "Request failed.");
    }

    return data;
}

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function formatDateTime(value) {
    if (!value) return "-";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "-";
    }

    return date.toLocaleString("en-IN", {
        dateStyle: "medium",
        timeStyle: "short"
    });
}

async function getMyProfile() {
    return await apiRequest("/api/me");
}

function requireLoggedIn() {
    return new Promise((resolve, reject) => {
        const unsubscribe = auth.onAuthStateChanged(user => {
            unsubscribe();

            if (user) {
                resolve(user);
            } else {
                window.location.replace("index.html");
                reject(new Error("Login required."));
            }
        });
    });
}

async function requireRole(...allowedRoles) {
    await requireLoggedIn();

    const profile = await getMyProfile();

    const role =
        profile &&
        profile.user &&
        profile.user.role;

    if (!allowedRoles.includes(role)) {
        await auth.signOut();

        alert("You are not authorized to access this page.");

        window.location.replace("index.html");

        throw new Error("Unauthorized role.");
    }

    return profile;
}

async function logout() {
    await auth.signOut();
    window.location.replace("index.html");
}