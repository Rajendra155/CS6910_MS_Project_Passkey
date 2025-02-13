const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const users={};

app.post('/webauthn/register',function(req,res){
    const{username} = req.body;

    const userid = crypto.randomBytes(32).toString('base64');
    const challenge = crypto.randomBytes(32).toString('base64');
    
   

    // Define the WebAuthn options for registration
    const publicKeyCredentialCreationOptions = {
        challenge: challenge,
        rp: {
            name: 'WebAuthn Demo',
            id:'localhost'
        },
        user: {
            id: userid, 
            name: username,
            displayName: username,
        },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }], // ES256
        authenticatorSelection: {
            authenticatorAttachment: 'platform',
            residentkey:'required',
            userVerification: 'required', // Ensure user verification is required
        },
        attestation:'none',
    };

    users[username] = { challenge, credential: null };


    res.json(publicKeyCredentialCreationOptions);
})


// Endpoint to complete registration
app.post('/webauthn/register/complete', (req, res) => {
    const { username, credential } = req.body;
    if (!username || !credential) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    // Store the credential (public key) for the user
    users[username].credential = credential;
    res.json({ success: true });

    console.log(JSON.stringify(credential, null, 2));
});


app.listen(5200,()=>{
    console.log('Server running on port 5200......')
})