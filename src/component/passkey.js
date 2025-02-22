import React, { useState } from 'react';
import axios from 'axios';

function Passkey() {
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');

  // This is a helper function to convert base64url to base64
  const base64UrlToBase64 = (base64url) => {
    // Add padding
    const padding = '='.repeat((4 - base64url.length % 4) % 4);

    // Convert base64url to base64 by replacing characters
    return base64url
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      + padding;
  };


  // Helper function to convert base64url to binary array
  const base64UrlToUint8Array = (base64url) => {
    // First convert base64url to base64
    const base64 = base64UrlToBase64(base64url);
    
    // Then convert base64 to binary
    const binary = atob(base64);
    // Convert to Uint8Array
    return new Uint8Array(binary.split('').map(c => c.charCodeAt(0)));
  };

  const handleRegister = async () => {
    if (!email) {
      setError('Please enter your email');
      return;
    }

    setError('');
    try {
      const { data: publicKeyCredentialCreationOptions } = await axios.post('http://localhost:5200/webauthn/register', { email });

      const publicKeyCredentialCreationOptionsParsed = {
        // Convert base64url challenge to Uint8Array
        challenge: base64UrlToUint8Array(publicKeyCredentialCreationOptions.challenge),
        rp: publicKeyCredentialCreationOptions.rp,
        user: {
          // Convert base64url user.id to Uint8Array
          id: base64UrlToUint8Array(publicKeyCredentialCreationOptions.user.id),
          name: publicKeyCredentialCreationOptions.user.name,
          displayName: publicKeyCredentialCreationOptions.user.displayName
        },
        pubKeyCredParams: publicKeyCredentialCreationOptions.pubKeyCredParams,
        authenticatorSelection: publicKeyCredentialCreationOptions.authenticatorSelection,
      };

      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptionsParsed,
      });

      await axios.post('http://localhost:5200/webauthn/register/complete', {
        email,
        credential,
      });

      window.alert('Registration successful');
      setEmail('');

    } catch (error) {
      console.error('Registration failed:', error);
      setError('Registration failed: ' + error.message);
    }
  };

  const handleAuthenticate = async () => {
    if (!email) {
      setError('Email is required');
      return;
    }

    try {
      const { data: publicKeyCredentialRequestOptions } = await axios.post(
        'http://localhost:5200/webauthn/authenticate',
        { email }
      );

      const publicKeyCredentialRequestOptionsParsed = {
        // Convert base64url challenge to Uint8Array
        challenge: base64UrlToUint8Array(publicKeyCredentialRequestOptions.challenge),
        allowCredentials: [{
          type: 'public-key',
          // Convert base64url credential ID to Uint8Array
          id: base64UrlToUint8Array(publicKeyCredentialRequestOptions.allowCredentials[0].id),
          transports: ['internal']
        }],
        userVerification: publicKeyCredentialRequestOptions.userVerification
      };

      const assertion = await navigator.credentials.get({ 
        publicKey: publicKeyCredentialRequestOptionsParsed 
      });

      const assertionResponse = {
        id: assertion.id,
        rawId: btoa(String.fromCharCode(...new Uint8Array(assertion.rawId))),
        type: assertion.type,
        response: {
          authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
          clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON))),
          signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature))),
          userHandle: assertion.response.userHandle ? 
            btoa(String.fromCharCode(...new Uint8Array(assertion.response.userHandle))) : 
            null
        }
      };

      await axios.post('http://localhost:5200/webauthn/authenticate/complete', {
        email,
        assertion: assertionResponse
      });

      window.alert('Authentication successful');
      setEmail('');

    } catch (error) {
      console.error('Authentication failed:', error);
      setError('Authentication failed: ' + error.message);
    }
  };

  // Rest of your component remains the same...
  return (
    <div style={{ textAlign: "center", marginTop: "50px" }}>
      <h2>WebAuthn Authentication</h2>
      <input
        type="email"
        placeholder="Enter your email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        style={{ padding: "10px", marginRight: "10px" }}
      />
      <br />
      {error && <p style={{color:'red'}}>{error}</p>}
      <br />
      <button onClick={handleRegister} style={{ padding: "10px", marginRight: "10px", background: "blue", color: "white" }}>
        Register
      </button>
      <button onClick={handleAuthenticate} style={{ padding: "10px", background: "green", color: "white" }}>
        Authenticate
      </button>
    </div>
  );
}

export default Passkey;