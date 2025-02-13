import React, {useState} from 'react';
import axios from 'axios';

function Passkey(){
    const [username, setUsername] = useState('');

    const handleRegister = async () =>{
    
        try{
      const {data: publicKeyCredentialCreationOptions} = await axios.post('http://localhost:5200/webauthn/register',{username});

          // Step 2: Create the publicKey object for the WebAuthn API
          const publicKeyCredentialCreationOptionsParsed = {
            challenge: new Uint8Array(
                atob(publicKeyCredentialCreationOptions.challenge)
                .split('')
                .map(c => c.charCodeAt(0))
            ),
            rp: publicKeyCredentialCreationOptions.rp,
            user: {
                id: new Uint8Array(
                    atob(publicKeyCredentialCreationOptions.user.id)
                    .split('')
                    .map(c => c.charCodeAt(0))
                ),
                name: publicKeyCredentialCreationOptions.user.name,
                displayName: publicKeyCredentialCreationOptions.user.displayName
            },
            pubKeyCredParams: publicKeyCredentialCreationOptions.pubKeyCredParams,
            authenticatorSelection: publicKeyCredentialCreationOptions.authenticatorSelection,
        };
       
        // Step 3: Call WebAuthn API to create credentials
        const credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptionsParsed,
        });

        // Step 4: Send the credential to the server to complete registration
        await axios.post('http://localhost:5200/webauthn/register/complete', {
            username,
            credential,
        });
        
        
        window.alert('Registration successful');
        setUsername('');

        }catch(error){
            console.error('Registration failed:', error);
        }

    }
   return(
    <div style={{ textAlign: "center", marginTop: "50px" }}>
            <h2>WebAuthn Authentication</h2>
            <input
                type="text"
                placeholder="Enter your name"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                style={{ padding: "10px", marginRight: "10px" }}
            />
            <br /><br />
            <button onClick={handleRegister} style={{ padding: "10px", marginRight: "10px", background: "blue", color: "white" }}>
                Register
            </button>
            <button  style={{ padding: "10px", background: "green", color: "white" }}>
                Authenticate
            </button>
    </div>
   )
}

export default Passkey;