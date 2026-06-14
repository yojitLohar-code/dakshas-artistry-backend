const pool = require('./db');
require('dotenv').config();

console.log("Attempting to connect with:");
console.log("Host:", process.env.DB_HOST);
console.log("User:", process.env.DB_USER);
console.log("Password:", process.env.DB_PASSWORD);
console.log("Database:", process.env.DB_NAME);

async function testConnection() {
    try {
        const connection = await pool.getConnection();
        console.log("✅ SUCCESS: Database connected perfectly!");
        connection.release();
        process.exit(0);
    } catch (err) {
        console.error("❌ ERROR: Could not connect to the database.");
        console.error("Error Code:", err.code);
        process.exit(1);
    }
}
testConnection();