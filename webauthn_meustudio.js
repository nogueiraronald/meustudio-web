// Helper WebAuthn para Touch ID (Mac), Windows Hello e Face ID no navegador (Chrome, Safari, Edge)
(function () {
  function bufToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function base64UrlToBuf(base64Url) {
    const pad = '='.repeat((4 - (base64Url.length % 4)) % 4);
    const base64 = (base64Url + pad).replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  window.meustudioWebAuthnDisponivel = async function () {
    try {
      if (
        typeof window.PublicKeyCredential === 'undefined' ||
        typeof navigator.credentials === 'undefined'
      ) {
        return false;
      }
      if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'function') {
        return false;
      }
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (_) {
      return false;
    }
  };

  window.meustudioWebAuthnRegistrar = async function (identificador) {
    try {
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);
      const userId = new TextEncoder().encode(String(identificador || 'usuario'));

      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: challenge,
          rp: {
            name: 'MeuStudio',
            id: window.location.hostname,
          },
          user: {
            id: userId,
            name: String(identificador || 'usuario'),
            displayName: String(identificador || 'Usuário MeuStudio'),
          },
          pubKeyCredParams: [
            { alg: -7, type: 'public-key' },
            { alg: -257, type: 'public-key' },
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'preferred',
          },
          timeout: 60000,
          attestation: 'none',
        },
      });

      if (!credential || !credential.rawId) {
        return '';
      }
      return bufToBase64Url(credential.rawId);
    } catch (_) {
      return '';
    }
  };

  window.meustudioWebAuthnAutenticar = async function (credentialIdB64) {
    try {
      if (!credentialIdB64) return false;
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: challenge,
          rpId: window.location.hostname,
          allowCredentials: [
            {
              id: base64UrlToBuf(credentialIdB64),
              type: 'public-key',
              transports: ['internal'],
            },
          ],
          userVerification: 'required',
          timeout: 60000,
        },
      });

      return Boolean(assertion);
    } catch (_) {
      return false;
    }
  };
})();
