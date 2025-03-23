const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const mysql = require('mysql2/promise'); 
const fs = require('fs');
require('dotenv').config();

const { verifyRegistrationResponse, verifyAuthenticationResponse } = require('@simplewebauthn/server');

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
        const challengeBuffer = crypto.randomBytes(32);
        const challenge = base64url.encode(challengeBuffer);

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
        const [challengeResults] = await connection.query('SELECT challenge, user_id FROM users WHERE email = ?', [email]);

        if (challengeResults.length === 0 || !challengeResults[0].challenge) {
            connection.release();
            return res.status(400).json({ error: 'Invalid authentication request' });
        }

        const storedChallenge = challengeResults[0].challenge;
        const userId = challengeResults[0].user_id;

        const verification = await verifyRegistrationResponse({
            response: credential,
            expectedChallenge: storedChallenge,
            expectedOrigin: 'https://passkeyauthentication.netlify.app',
            expectedRPID: 'passkeyauthentication.netlify.app',
        });

        const { verified, registrationInfo } = verification;

        if (verified && registrationInfo) {
            let credentialPublicKeyBase64 = null;
            let credentialIDBase64url = null;
            const initialCounter = 0;

            if (registrationInfo.credential && registrationInfo.credential.id) {
                credentialIDBase64url = registrationInfo.credential.id;
            }

            if (registrationInfo.credential && registrationInfo.credential.publicKey) {
                credentialPublicKeyBase64 = Buffer.from(registrationInfo.credential.publicKey).toString('base64');
            }

            const insertCredentialQuery = `UPDATE users SET credential = ?, public_key = ?, credential_id = ?, counter = ? WHERE email = ?`;
            await connection.query(insertCredentialQuery, [JSON.stringify(registrationInfo), credentialPublicKeyBase64, credentialIDBase64url, initialCounter, email]);

            connection.release();
            res.json({ success: true });
            console.log(`Credential and public key saved for ${email}`);
            if (credentialPublicKeyBase64) console.log('Public Key (Base64):', credentialPublicKeyBase64);
            if (credentialIDBase64url) console.log('Credential ID (Base64URL):', credentialIDBase64url);
        } else {
            connection.release();
            return res.status(400).json({ error: 'Registration verification failed' });
        }
    } catch (err) {
        console.error('Error storing credential:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

// --- /webauthn/authenticate -----
app.post('/webauthn/authenticate', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    try {
        const connection = await pool.getConnection();

        // Generate a new challenge (using base64url encoding)
        const challengeBuffer = crypto.randomBytes(32);
        const challenge = base64url.encode(challengeBuffer);

        console.log("Generated challenge for authentication:", challenge);

        // Store challenge in database
        await connection.query('UPDATE users SET challenge = ? WHERE email = ?', [challenge, email]);

        // Retrieve the credential ID for this user
        const [results] = await connection.query('SELECT credential_id FROM users WHERE email = ?', [email]);

        if (results.length === 0 || !results[0].credential_id) {
            connection.release();
            return res.status(400).json({ error: 'User not found or not registered' });
        }

        const credentialId = results[0].credential_id;

        // Send authentication request to frontend
        const publicKeyCredentialRequestOptions = {
            challenge: challenge,
            allowCredentials: [
                {
                    type: 'public-key',
                    id: credentialId,
                    transports: ['internal'],
                }
            ],
            userVerification: 'required',
            timeout: 60000,
        };

        connection.release();
        res.json(publicKeyCredentialRequestOptions);
    } catch (err) {
        console.error('Error in /webauthn/authenticate:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

app.post('/webauthn/authenticate/complete', async (req, res) => {
    const { email, assertion } = req.body;

    if (!email || !assertion) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    try {
        const connection = await pool.getConnection();

        const [results] = await connection.query('SELECT challenge, public_key, credential_id, counter FROM users WHERE email = ?', [email]);

        if (results.length === 0) {
            connection.release();
            return res.status(400).json({ error: 'User not found' });
        }

        const userData = results[0];

        if (!userData.challenge) {
            connection.release();
            return res.status(400).json({ error: 'No active authentication request' });
        }

        if (!userData.public_key || !userData.credential_id) {
            connection.release();
            return res.status(400).json({ error: 'User not properly registered' });
        }

        const storedChallenge = userData.challenge;
        const publicKeyBase64 = userData.public_key;
        const credentialId = userData.credential_id;
        const storedCounter = typeof userData.counter === 'number' ? userData.counter : 0;

        // Helper function to ensure base64url format
        const toBase64Url = (str) => {
            if (!/[+/=]/.test(str)) {
                return str;
            }
            return str.replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=+$/, '');
        };

        // Properly format all parts of the assertion for WebAuthn verification
        const formattedAssertion = {
            id: toBase64Url(assertion.id || assertion.rawId),
            rawId: toBase64Url(assertion.rawId || assertion.id),
            type: assertion.type,
            response: {
                clientDataJSON: toBase64Url(assertion.response.clientDataJSON),
                authenticatorData: toBase64Url(assertion.response.authenticatorData),
                signature: toBase64Url(assertion.response.signature)
            }
        };

        // Add userHandle if it exists
        if (assertion.response.userHandle) {
            formattedAssertion.response.userHandle = toBase64Url(assertion.response.userHandle);
        }

        const verification = await verifyAuthenticationResponse({
            response: formattedAssertion,
            expectedChallenge: storedChallenge,
            expectedOrigin: 'https://passkeyauthentication.netlify.app', // Update with your origin
            expectedRPID: 'passkeyauthentication.netlify.app', // Update with your RPID
            credential: {
                id: credentialId,
                publicKey: Buffer.from(publicKeyBase64, 'base64'),
                credentialPublicKey: Buffer.from(publicKeyBase64, 'base64'),
                counter: storedCounter
            },
            requireUserVerification: true,
        });

        console.log('Library verification successful:', JSON.stringify(verification, null, 2));

        // Extract the new counter value from verification result
        const newCounter = verification.authenticationInfo.newCounter;
        console.log('Authentication successful for user:', email);

        // Update the counter and clear the challenge
        await connection.query('UPDATE users SET challenge = NULL, counter = ? WHERE email = ?', [newCounter, email]);

        connection.release();

        res.json({
            success: true,
            message: 'Authentication successful'
        });
    } catch (error) {
        console.error('Authentication verification error:', error);
        return res.status(400).json({
            error: 'Authentication failed',
            details: error.message
        });
    }
});

const PORT = process.env.PORT || 5200;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}...`);
});

