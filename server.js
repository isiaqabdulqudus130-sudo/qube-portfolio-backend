const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());


// ===============================
// DATABASE
// ===============================

const pool = mysql.createPool({
    host: process.env.MYSQLHOST,
    port: process.env.MYSQLPORT,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE
});


// ===============================
// TEMPORARY ADMIN AUTH STORAGE
// ===============================

let pendingOTP = null;
let adminSession = null;


// ===============================
// BASIC ROUTE
// ===============================

app.get("/", (req, res) => {
    res.json({
        message: "Qube Portfolio Backend is running!"
    });
});


// ===============================
// CONTACT FORM
// ===============================

app.post("/api/messages", async (req, res) => {
    try {
        const { name, email, subject, message } = req.body;

        if (!name || !email || !message) {
            return res.status(400).json({
                success: false,
                message: "Name, email and message are required."
            });
        }

        const sql = `
            INSERT INTO messages
            (name, email, subject, message)
            VALUES (?, ?, ?, ?)
        `;

        await pool.execute(sql, [
            name,
            email,
            subject || null,
            message
        ]);

        res.status(201).json({
            success: true,
            message: "Your message has been received successfully."
        });

    } catch (error) {
        console.error("Database error:", error);

        res.status(500).json({
            success: false,
            message: "Something went wrong. Please try again later."
        });
    }
});


// ===============================
// ADMIN LOGIN - STEP 1
// EMAIL + PASSWORD
// ===============================

app.post("/api/admin/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required."
            });
        }

        // Check admin email
        if (
            email.toLowerCase() !==
            process.env.ADMIN_EMAIL.toLowerCase()
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid admin credentials."
            });
        }

        // Check admin password
        if (password !== process.env.ADMIN_PASSWORD) {
            return res.status(401).json({
                success: false,
                message: "Invalid admin credentials."
            });
        }


        // ===============================
        // GENERATE 6-DIGIT OTP
        // ===============================

        const otp = crypto
            .randomInt(100000, 1000000)
            .toString();


        // Store OTP
        pendingOTP = {
            code: otp,
            expiresAt: Date.now() + 5 * 60 * 1000,
            attempts: 0
        };


        // ===============================
        // SEND OTP THROUGH GOOGLE APPS SCRIPT
        // ===============================

        const emailResponse = await fetch(
            process.env.GOOGLE_SCRIPT_URL,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    to: process.env.ADMIN_EMAIL,

                    subject:
                        "Qube Portfolio Admin Login OTP",

                    message:
                        `Your Qube Portfolio admin login OTP is: ${otp}

This OTP expires in 5 minutes.

If you did not attempt to log in, please ignore this email.`
                })
            }
        );


        const emailData =
            await emailResponse.json();


        // Make sure Google Apps Script succeeded
        if (
            !emailResponse.ok ||
            !emailData.success
        ) {
            throw new Error(
                "Google email service failed."
            );
        }


        // ===============================
        // SUCCESS
        // ===============================

        res.json({
            success: true,
            message: "OTP sent successfully.",
            requiresOTP: true
        });

    } catch (error) {

        console.error(
            "Admin login error:",
            error
        );

        // Remove OTP if email failed
        pendingOTP = null;

        res.status(500).json({
            success: false,
            message:
                "Unable to send OTP. Please try again."
        });
    }
});


// ===============================
// ADMIN LOGIN - STEP 2
// VERIFY OTP
// ===============================

app.post("/api/admin/verify-otp", (req, res) => {
    try {

        const { otp } = req.body;


        // No active OTP
        if (!pendingOTP) {
            return res.status(400).json({
                success: false,
                message:
                    "No active OTP. Please login again."
            });
        }


        // ===============================
        // CHECK OTP EXPIRATION
        // ===============================

        if (
            Date.now() >
            pendingOTP.expiresAt
        ) {

            pendingOTP = null;

            return res.status(401).json({
                success: false,
                message:
                    "OTP has expired. Please login again."
            });
        }


        // ===============================
        // LIMIT OTP ATTEMPTS
        // ===============================

        if (pendingOTP.attempts >= 5) {

            pendingOTP = null;

            return res.status(401).json({
                success: false,
                message:
                    "Too many incorrect attempts. Please login again."
            });
        }


        // Count this attempt
        pendingOTP.attempts++;


        // ===============================
        // CHECK OTP
        // ===============================

        if (otp !== pendingOTP.code) {

            return res.status(401).json({
                success: false,
                message:
                    "Invalid OTP."
            });
        }


        // ===============================
        // OTP SUCCESS
        // ===============================

        pendingOTP = null;


        // Create admin session token
        adminSession =
            crypto.randomBytes(32).toString("hex");


        res.json({
            success: true,
            message:
                "Admin login successful.",
            token: adminSession
        });

    } catch (error) {

        console.error(
            "OTP verification error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Something went wrong."
        });
    }
});


// ===============================
// ADMIN AUTH MIDDLEWARE
// ===============================

function requireAdmin(req, res, next) {

    const authHeader =
        req.headers.authorization;


    if (
        !authHeader ||
        !authHeader.startsWith("Bearer ")
    ) {

        return res.status(401).json({
            success: false,
            message:
                "Unauthorized."
        });
    }


    const token =
        authHeader.split(" ")[1];


    if (
        !adminSession ||
        token !== adminSession
    ) {

        return res.status(401).json({
            success: false,
            message:
                "Unauthorized."
        });
    }


    next();
}


// ===============================
// ADMIN DASHBOARD TEST
// ===============================

app.get(
    "/api/admin/check",
    requireAdmin,
    (req, res) => {

        res.json({
            success: true,
            message:
                "Admin authentication verified."
        });
    }
);


// ===============================
// ADMIN LOGOUT
// ===============================

app.post(
    "/api/admin/logout",
    requireAdmin,
    (req, res) => {

        adminSession = null;

        res.json({
            success: true,
            message:
                "Logged out successfully."
        });
    }
);


// ===============================
// START SERVER
// ===============================

app.listen(
    PORT,
    "0.0.0.0",
    () => {
        console.log(
            `Qube backend running on port ${PORT}`
        );
    }
);
