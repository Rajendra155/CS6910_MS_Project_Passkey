const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const mysql = require('mysql');


const app = express();
app.use(cors());
app.use(bodyParser.json());

const users = {}; // Store users by email


var con =mysql.createConnection({
    host:'localhost',
    user:"root",
    password:"Hashtag@123",
    database:'webauthn_passkey'
})

con.connect(function(err,result){
    if(err)
    {
        console.log('Error connectiong to database');
        return;
    }
    console.log('Connected to Database');

})

app.post('/webauthn/register', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    // Check if the user already exists
    const checkUserQuery = `SELECT * FROM users WHERE email = ?`;
    con.query(checkUserQuery, [email], (err, results) => {
        if (err) {
            console.error('Error checking user:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length > 0) {
            // If user already exists, return a message
            console.error('Email already exists',err);
            return res.status(400).json({ error: 'User already exists' });
        }

        // Proceed with registration if the user doesn't exist
        const userId = crypto.randomBytes(32).toString('base64');
        const challenge = crypto.randomBytes(32).toString('base64');

        // Store the new user and challenge in the database
        const insertUserQuery = `
            INSERT INTO users (email, user_id, challenge) 
            VALUES (?, ?, ?)
        `;
        con.query(insertUserQuery, [email, userId, challenge], (err) => {
            if (err) {
                console.error('Error storing challenge:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            // Define WebAuthn options for registration
            const publicKeyCredentialCreationOptions = {
                challenge: challenge,
                rp: {
                    name: 'Passwordless login',
                    id: 'localhost'
                },
                user: {
                    id: userId,
                    name: email,
                    displayName: email,
                },
                pubKeyCredParams: [{ type: 'public-key', alg: -7 },
                    { type: 'public-key', alg: -257 }
                ], // ES256 RS256
                authenticatorSelection: {
                    authenticatorAttachment: 'platform',
                    residentKey: 'required',
                    userVerification: 'required',
                },
                attestation: 'direct',
            };

            // Respond with WebAuthn options
            res.json(publicKeyCredentialCreationOptions);
        });
    });
});


// Endpoint to complete registration
app.post('/webauthn/register/complete', (req, res) => {
    const { email, credential } = req.body;
    if (!email || !credential) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    const updateCredentialQuery = `
    UPDATE users 
    SET credential = ? 
    WHERE email = ?
`;

// Credential was stored in JSON format
con.query(updateCredentialQuery, [JSON.stringify(credential), email], (err) => {
    if (err) {
        console.error('Error storing credential:', err);
        return res.status(500).json({ error: 'Database error' });
    }

    res.json({ success: true });
    console.log(`Credential saved for ${email}`);
});
});

// Begin authentication
app.post('/webauthn/authenticate', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

 
// It will retrieve the credential from users table based on given email
    const getUserQuery = `SELECT credential FROM users WHERE email = ?`;

   
    con.query(getUserQuery, [email], (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            //If user is not found returns a 400 error
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0 || !results[0].credential) {
            return res.status(400).json({ error: 'User not registered' });
        }

        //Converts the stored credential (which is saved as a JSON string) back into an object.
        const credential = JSON.parse(results[0].credential);

        //generates a new challenge
        const challenge = crypto.randomBytes(32).toString('base64');

        // Store challenge in database
        const updateChallengeQuery = `UPDATE users SET challenge = ? WHERE email = ?`;
        con.query(updateChallengeQuery, [challenge, email], (err) => {
            if (err) {
                console.error('Error updating challenge:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            // Send authentication request to frontend
            const publicKeyCredentialRequestOptions = {
                challenge: challenge,
                allowCredentials: [
                    {
                        type: 'public-key',
                        id: credential.rawId, // Registered credential ID
                        transports: ['internal'],
                    }
                ],
                userVerification: 'required',
            };
            res.json(publicKeyCredentialRequestOptions);
        });
    });
    
    
});

// Verify authentication response
app.post('/webauthn/authenticate/complete', (req, res) => {
    const { email, assertion } = req.body;

    if (!email || !assertion) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    //Retrieve stored challenge from database 
    const getChallengeQuery =`select challenge from users where email = ?`;


    con.query(getChallengeQuery,[email],(err,results) => {
    if(err)
    {
        console.log('Error fecthing challenge');
        return res.status(500).json({ error: 'Database error' });
    }

    if (results.length === 0 || !results[0].challenge) {
        return res.status(400).json({ error: 'Invalid authentication request' });
    }
   
    const storedChallenge = results[0].challenge;

        console.log('User authenticated:', email);

    // Clear challenge after successful authentication
    const clearChallengeQuery = `UPDATE users SET challenge = NULL WHERE email = ?`;
    con.query(clearChallengeQuery, [email], (err) => {
        if (err) {
            console.error('Error clearing challenge:', err);
        }
    });

    res.json({ success: true });



    })
});

app.listen(5200, () => {
    console.log('Server running on port 5200...');
});
