'use strict';

let pending = null;
let registeredCredential = null;
const protocol = document.querySelector('#protocol');
const createButton = document.querySelector('#create');
const authenticateButton = document.querySelector('#authenticate');
const cancelButton = document.querySelector('#cancel');
const output = document.querySelector('#result');
const available = window.isSecureContext && location.hostname === 'localhost'
  && Boolean(navigator.credentials && window.PublicKeyCredential);

function log(message) {
  output.textContent += `${new Date().toISOString()} ${message}\n`;
}

function updateButtons() {
  createButton.disabled = !available || pending !== null;
  authenticateButton.disabled = !available || pending !== null || registeredCredential === null;
  cancelButton.disabled = pending === null;
  protocol.disabled = pending !== null;
}

function updateInstructions() {
  document.querySelector('#instructions').textContent = protocol.value === 'u2f'
    ? 'Enable U2F and disable FIDO2 on the device. U2F retries sample touch once per request. Its blink stops on successful touch or shortly after polling ends; the browser may wait longer than the requested 30 seconds.'
    : 'Enable FIDO2 and disable U2F on the device. CTAP2 waits for touch for up to 30 seconds. Its blink stops on success, device timeout, or cancellation.';
}

async function perform(operation) {
  if (pending !== null || !available) return;
  const controller = new AbortController();
  pending = controller;
  updateButtons();
  const start = performance.now();
  const elapsed = () => ((performance.now() - start) / 1000).toFixed(3);
  log(`${protocol.value.toUpperCase()} qualification: ${operation} pending. Requested timeout: 30 seconds.`);
  try {
    if (operation === 'creation') {
      const credential = await navigator.credentials.create({
        signal: controller.signal,
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rp: { id: 'localhost', name: 'Local FIDO browser qualification' },
          user: {
            id: crypto.getRandomValues(new Uint8Array(16)),
            name: 'local-test',
            displayName: 'Local test',
          },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          authenticatorSelection: {
            authenticatorAttachment: 'cross-platform',
            residentKey: 'discouraged',
            requireResidentKey: false,
            userVerification: 'discouraged',
          },
          attestation: 'direct',
          timeout: 30000,
          hints: ['security-key'],
        },
      });
      if (!credential) throw new Error('The browser returned no credential.');
      registeredCredential = credential;
      log(`Creation succeeded after ${elapsed()} seconds. Credential ID length: ${credential.rawId.byteLength} bytes. Ready to authenticate.`);
    } else {
      const assertion = await navigator.credentials.get({
        signal: controller.signal,
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: 'localhost',
          allowCredentials: [{
            type: 'public-key', id: registeredCredential.rawId, transports: ['usb'],
          }],
          userVerification: 'discouraged',
          timeout: 30000,
          hints: ['security-key'],
        },
      });
      if (!assertion) throw new Error('The browser returned no assertion.');
      log(`Authentication succeeded after ${elapsed()} seconds. Signature length: ${assertion.response.signature.byteLength} bytes.`);
    }
  } catch (error) {
    log(`${error.name} after ${elapsed()} seconds: ${error.message}`);
  } finally {
    pending = null;
    updateButtons();
  }
}

protocol.onchange = () => {
  registeredCredential = null;
  updateInstructions();
  updateButtons();
  log('Protocol instructions changed; create a credential after configuring the device.');
};
createButton.onclick = () => perform('creation');
authenticateButton.onclick = () => {
  if (registeredCredential !== null) return perform('authentication');
};
cancelButton.onclick = () => {
  log('WebAuthn abort requested by the page.');
  pending?.abort();
};

output.textContent = '';
updateInstructions();
updateButtons();
log(available
  ? `Ready. Browser: ${navigator.userAgent}`
  : 'WebAuthn unavailable. Open this page at http://localhost using a browser with WebAuthn support.');
