
import { initializeApp } from "https://www.gstatic.com/firebasejs/13.4.0/firebase-app.js";

import {
    getAuth,
    signInAnonymously
} from "https://www.gstatic.com/firebasejs/13.4.0/firebase-auth.js";

import {
    getStorage
} from "https://www.gstatic.com/firebasejs/13.4.0/firebase-storage.js";

const firebaseConfig = {
  apiKey: "AIzaSyD0fTcd3fS6F3Ac2UkV_UUiclMwqMyaqxA",
  authDomain: "staticshield-9854.firebaseapp.com",
  projectId: "staticshield-9854",
  storageBucket: "staticshield-9854.firebasestorage.app",
  messagingSenderId: "1086165331123",
  appId: "1:1086165331123:web:9eafced7c30024ce1754c6"
};

// Initialize Firebase.
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const storage = getStorage(app);

// Sign in anonymously.
async function initializeFirebase() {
    try {
        const user = auth.currentUser ||
            (await signInAnonymously(auth)).user;

        window.staticShieldFirebase = {
            app,
            auth,
            storage,
            user
        };

        console.log("Firebase initialized successfully.");
        console.log("Anonymous user:", user.uid);

        window.dispatchEvent(
            new Event("staticshield-firebase-ready")
        );

    } catch (error) {
        console.error("Firebase initialization failed:", error);
    }
}

initializeFirebase();
