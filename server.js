const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const pool = mysql.createPool({
    host: process.env.MYSQLHOST,
    port: process.env.MYSQLPORT,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE
});
pool.query(`
    ALTER TABLE messages
    MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT
`).then(() => {
    console.log("messages.id AUTO_INCREMENT fixed successfully");
}).catch((error) => {
    console.error("AUTO_INCREMENT fix error:", error);
});
app.get("/", (req, res) => {
    res.json({
        message: "Qube Portfolio Backend is running!"
    });
});

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

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Qube backend running on port ${PORT}`);
});
