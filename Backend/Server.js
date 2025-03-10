const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const mysql = require('mysql2/promise'); 
const fs = require('fs');
require('dotenv').config();

const app = express();
app.use(cors({
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
}));
app.use(bodyParser.json());

const pool = mysql.createPool({ // Create the connection pool
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT || '3306',
    ssl: {
        ca: fs.readFileSync('./isrgrootx1.pem'), // Correct path to your CA certificate
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test the database connection (optional)
async function testConnection() {
    try {
        const connection = await pool.getConnection();
        console.log('Connected to Database');
        connection.release();
    } catch (err) {
        console.error('Error connecting to database:', err);
    }
}
testConnection();

// --- /webauthn/register ---
app.post('/webauthn/register', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    try {
        const connection = await pool.getConnection();

        // Check if the user already exists
        const [results] = await connection.query('SELECT * FROM users WHERE email = ?', [email]);

        if (results.length > 0) {
            connection.release();
            return res.status(400).json({ error: 'User already exists' });
        }

        // Proceed with registration if the user doesn't exist
        const userId = crypto.randomBytes(32).toString('base64');
        const challenge = crypto.randomBytes(32).toString('base64');

        // Store the new user and challenge in the database
        await connection.query('INSERT INTO users (email, user_id, challenge) VALUES (?, ?, ?)', [email, userId, challenge]);

        connection.release();

        // Define WebAuthn options for registration
        const publicKeyCredentialCreationOptions = {
            challenge: challenge,
            rp: {
                name: 'Passwordless login',
                id: 'passkeyauthentication.netlify.app' 
            },
            user: {
                id: userId,
                name: email,
                displayName: email,
            },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
            authenticatorSelection: {
                authenticatorAttachment: 'platform',
                residentKey: 'required',
                userVerification: 'required',
            },
            attestation: 'direct',
        };

        res.json(publicKeyCredentialCreationOptions);
    } catch (err) {
        console.error('Error in /webauthn/register:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

// --- /webauthn/register/complete ---
app.post('/webauthn/register/complete', async (req, res) => {
    const { email, credential } = req.body;
    if (!email || !credential) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    try {
        const connection = await pool.getConnection();

        const updateCredentialQuery = `
            UPDATE users
            SET credential = ?
            WHERE email = ?
        `;

        await connection.query(updateCredentialQuery, [JSON.stringify(credential), email]);

        connection.release();

        res.json({ success: true });
        console.log(`Credential saved for ${email}`);
    } catch (err) {
        console.error('Error storing credential:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

// --- /webauthn/authenticate ---
app.post('/webauthn/authenticate', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    try {
        const connection = await pool.getConnection();

        const [results] = await connection.query('SELECT credential FROM users WHERE email = ?', [email]);

        if (results.length === 0 || !results[0].credential) {
            connection.release();
            return res.status(400).json({ error: 'User not registered' });
        }

        const credential = results[0].credential;
        const challenge = crypto.randomBytes(32).toString('base64');

        // Store challenge in database
        await connection.query('UPDATE users SET challenge = ? WHERE email = ?', [challenge, email]);

        connection.release();

        // Send authentication request to frontend
        const publicKeyCredentialRequestOptions = {
            challenge: challenge,
            allowCredentials: [
                {
                    type: 'public-key',
                    id: credential.rawId,
                    transports: ['internal'],
                }
            ],
            userVerification: 'required',
        };

        res.json(publicKeyCredentialRequestOptions);
    } catch (err) {
        console.error('Error in /webauthn/authenticate:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

// --- /webauthn/authenticate/complete ---
app.post('/webauthn/authenticate/complete', async (req, res) => {
    const { email, assertion } = req.body;

    if (!email || !assertion) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    try {
        const connection = await pool.getConnection();

        const [results] = await connection.query('SELECT challenge FROM users WHERE email = ?', [email]);

        if (results.length === 0 || !results[0].challenge) {
            connection.release();
            return res.status(400).json({ error: 'Invalid authentication request' });
        }

        const storedChallenge = results[0].challenge;

        // Perform assertion verification here (using storedChallenge and assertion)
        // ...

        // Clear challenge after successful authentication
        await connection.query('UPDATE users SET challenge = NULL WHERE email = ?', [email]);

        connection.release();

        console.log('User authenticated:', email);
        res.json({ success: true });
    } catch (err) {
        console.error('Error in /webauthn/authenticate/complete:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

const PORT = process.env.PORT || 5200;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}...`);
});

