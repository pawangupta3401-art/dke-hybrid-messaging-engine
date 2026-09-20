/**
 * Dynamic Key Evolution (DKE) — Web Demonstration Engine
 * Client-Side Real Cryptographic Simulation using Web Crypto API (SubtleCrypto)
 */

(function () {
  'use strict';

  // --------------------------------------------------------------------------
  // Utility & Conversion Helpers
  // --------------------------------------------------------------------------
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function toHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);
    return bytes;
  }

  // --------------------------------------------------------------------------
  // Cryptographic Primitives (HKDF-SHA256 & AES-256-GCM)
  // --------------------------------------------------------------------------
  const PROTOCOL_MAGIC = new Uint8Array([0x44, 0x4b, 0x45, 0x4d]); // 'DKEM'
  const PROTOCOL_VERSION = 1;
  const HEADER_SIZE = 30;
  const TAG_SIZE = 16;
  const RATCHET_INFO = encoder.encode('DKE-MESSAGE-KEY-EVOLUTION-V1');

  // Evolve key: K_{i+1} = HMAC-SHA256(K_i, nonce || RATCHET_INFO)
  async function ratchetDeriveKey(currentKeyBytes, nonceBytes) {
    const key = await window.crypto.subtle.importKey(
      'raw',
      currentKeyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const message = new Uint8Array(nonceBytes.length + RATCHET_INFO.length);
    message.set(nonceBytes, 0);
    message.set(RATCHET_INFO, nonceBytes.length);

    const signature = await window.crypto.subtle.sign('HMAC', key, message);
    return new Uint8Array(signature); // 32 bytes (256-bit key)
  }

  // Encrypt plaintext with AES-256-GCM
  async function encryptAESGCM(rawKeyBytes, plaintextBytes, nonceBytes) {
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      rawKeyBytes,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonceBytes,
        tagLength: 128 // 16 bytes
      },
      cryptoKey,
      plaintextBytes
    );

    // SubtleCrypto appends the 16-byte tag to the ciphertext
    const full = new Uint8Array(encrypted);
    const ctLen = full.length - TAG_SIZE;
    const ciphertext = full.subarray(0, ctLen);
    const tag = full.subarray(ctLen);
    return { ciphertext, tag };
  }

  // Decrypt ciphertext with AES-256-GCM
  async function decryptAESGCM(rawKeyBytes, ciphertextBytes, nonceBytes, tagBytes) {
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      rawKeyBytes,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // SubtleCrypto expects ciphertext + tag combined
    const combined = new Uint8Array(ciphertextBytes.length + tagBytes.length);
    combined.set(ciphertextBytes, 0);
    combined.set(tagBytes, ciphertextBytes.length);

    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonceBytes,
        tagLength: 128
      },
      cryptoKey,
      combined
    );

    return new Uint8Array(decrypted);
  }

  // Encode 30-byte envelope header (matching protocol.py '!4sBBQ12sI' exactly)
  function encodeHeader(seq, nonce, ctLen) {
    const header = new Uint8Array(HEADER_SIZE);
    const view = new DataView(header.buffer);

    // Magic: 4 bytes (0..3)
    header.set(PROTOCOL_MAGIC, 0);
    // Version: uint8 (offset 4)
    view.setUint8(4, PROTOCOL_VERSION);
    // Flags: uint8 (offset 5)
    view.setUint8(5, 0x00);
    // Sequence: uint64 (offset 6..13)
    view.setBigUint64(6, BigInt(seq), false);
    // Nonce: 12 bytes (offset 14..25)
    header.set(nonce, 14);
    // Ciphertext length: uint32 (offset 26..29)
    view.setUint32(26, ctLen, false);

    return header;
  }

  // Parse envelope (matching protocol.py '!4sBBQ12sI' exactly)
  function parseEnvelope(envelopeBytes) {
    if (envelopeBytes.length < HEADER_SIZE + TAG_SIZE) {
      throw new Error('Envelope smaller than minimum header + tag length');
    }
    const view = new DataView(envelopeBytes.buffer, envelopeBytes.byteOffset);
    // Check magic
    if (
      envelopeBytes[0] !== 0x44 ||
      envelopeBytes[1] !== 0x4b ||
      envelopeBytes[2] !== 0x45 ||
      envelopeBytes[3] !== 0x4d
    ) {
      throw new Error('Invalid protocol magic bytes');
    }

    const seq = Number(view.getBigUint64(6, false));
    const nonce = envelopeBytes.subarray(14, 26);
    const ctLen = view.getUint32(26, false);

    const expectedTotal = HEADER_SIZE + ctLen + TAG_SIZE;
    if (envelopeBytes.length !== expectedTotal) {
      throw new Error('Declared payload length mismatch');
    }

    const ciphertext = envelopeBytes.subarray(HEADER_SIZE, HEADER_SIZE + ctLen);
    const tag = envelopeBytes.subarray(HEADER_SIZE + ctLen, expectedTotal);

    return { seq, nonce, ciphertext, tag };
  }

  // --------------------------------------------------------------------------
  // Simulation State Machine
  // --------------------------------------------------------------------------
  const state = {
    active: false,
    k0: null,
    // Alice (Initiator)
    alice: {
      outKey: null,
      inKey: null,
      sentCount: 0,
      recvCount: 0,
      outSeq: 1,
      inSeq: 1
    },
    // Bob (Responder)
    bob: {
      outKey: null,
      inKey: null,
      sentCount: 0,
      recvCount: 0,
      outSeq: 1,
      inSeq: 1
    }
  };

  // DOM Elements
  const elStatusBadge = document.getElementById('sim-status-badge');
  const elBtnStart = document.getElementById('btn-sim-start');
  const elBtnEnd = document.getElementById('btn-sim-end');
  const elBtnTamper = document.getElementById('btn-sim-tamper');

  const elAliceTranscript = document.getElementById('alice-transcript');
  const elBobTranscript = document.getElementById('bob-transcript');
  const elAliceInput = document.getElementById('alice-input');
  const elBobInput = document.getElementById('bob-input');
  const elAliceSend = document.getElementById('btn-alice-send');
  const elBobSend = document.getElementById('btn-bob-send');

  const elAliceSentCount = document.getElementById('alice-sent-count');
  const elAliceRecvCount = document.getElementById('alice-recv-count');
  const elBobSentCount = document.getElementById('bob-sent-count');
  const elBobRecvCount = document.getElementById('bob-recv-count');

  const elInspK0 = document.getElementById('insp-k0');
  const elInspAliceOut = document.getElementById('insp-alice-out');
  const elInspBobOut = document.getElementById('insp-bob-out');
  const elInspLastNonce = document.getElementById('insp-last-nonce');
  const elBtnToggleWire = document.getElementById('btn-toggle-wire');

  let allWireExpanded = false;

  function appendChat(transcriptEl, text, className, wireData = null) {
    if (!wireData) {
      const line = document.createElement('div');
      line.className = 'chat-line ' + className;
      line.textContent = text;
      transcriptEl.appendChild(line);
      transcriptEl.scrollTop = transcriptEl.scrollHeight;
      return;
    }

    const group = document.createElement('div');
    group.className = 'chat-message-group';

    const line = document.createElement('div');
    line.className = 'chat-line ' + className;
    line.textContent = text;
    group.appendChild(line);

    const details = document.createElement('details');
    details.className = 'wire-details';
    if (allWireExpanded) {
      details.open = true;
    }

    const summary = document.createElement('summary');
    summary.className = 'wire-summary';
    summary.innerHTML = `<span class="wire-badge ${wireData.tampered ? 'corrupted' : ''}">Wire View</span> ${wireData.tampered ? 'Tampered Network Packet' : 'Encrypted Wire Frame'}`;
    details.appendChild(summary);

    const body = document.createElement('div');
    body.className = 'wire-body';

    body.innerHTML = `
      <div class="wire-field">
        <span class="wire-key">Sequence:</span>
        <span class="wire-val">${wireData.seq}</span>
      </div>
      <div class="wire-field">
        <span class="wire-key">Nonce (12B):</span>
        <span class="wire-val">${toHex(wireData.nonce)}</span>
      </div>
      <div class="wire-field">
        <span class="wire-key">Ciphertext (${wireData.ciphertext.length}B):</span>
        <span class="wire-val ${wireData.tampered ? 'tampered-byte' : ''}">${toHex(wireData.ciphertext)}</span>
      </div>
      <div class="wire-field">
        <span class="wire-key">Auth Tag (16B):</span>
        <span class="wire-val">${toHex(wireData.tag)}</span>
      </div>
      <div class="wire-field">
        <span class="wire-key">Wire Frame (${wireData.rawEnvelope.length}B):</span>
        <span class="wire-val wire-frame">${toHex(wireData.rawEnvelope)}</span>
      </div>
    `;

    details.appendChild(body);
    group.appendChild(details);

    transcriptEl.appendChild(group);
    transcriptEl.scrollTop = transcriptEl.scrollHeight;
  }

  function updateUI() {
    if (state.active) {
      elStatusBadge.textContent = 'Active';
      elStatusBadge.className = 'status-badge active';
      elBtnStart.style.display = 'none';
      elBtnEnd.style.display = 'inline-flex';
      elBtnTamper.disabled = false;
      elAliceInput.disabled = false;
      elBobInput.disabled = false;
      elAliceSend.disabled = false;
      elBobSend.disabled = false;

      elAliceSentCount.textContent = state.alice.sentCount;
      elAliceRecvCount.textContent = state.alice.recvCount;
      elBobSentCount.textContent = state.bob.sentCount;
      elBobRecvCount.textContent = state.bob.recvCount;

      elInspK0.textContent = state.k0 ? toHex(state.k0).substring(0, 16) + '...' : 'None';
      elInspAliceOut.textContent = state.alice.outKey ? toHex(state.alice.outKey).substring(0, 16) + '...' : 'None';
      elInspBobOut.textContent = state.bob.outKey ? toHex(state.bob.outKey).substring(0, 16) + '...' : 'None';
    } else {
      elStatusBadge.textContent = 'Idle';
      elStatusBadge.className = 'status-badge idle';
      elBtnStart.style.display = 'inline-flex';
      elBtnEnd.style.display = 'none';
      elBtnTamper.disabled = true;
      elAliceInput.disabled = true;
      elBobInput.disabled = true;
      elAliceSend.disabled = true;
      elBobSend.disabled = true;

      elAliceSentCount.textContent = '0';
      elAliceRecvCount.textContent = '0';
      elBobSentCount.textContent = '0';
      elBobRecvCount.textContent = '0';

      elInspK0.textContent = 'None';
      elInspAliceOut.textContent = 'None';
      elInspBobOut.textContent = 'None';
      elInspLastNonce.textContent = 'None';
    }
  }

  // --------------------------------------------------------------------------
  // Handshake & Lifecycle Actions
  // --------------------------------------------------------------------------
  async function startSession() {
    appendChat(elAliceTranscript, '[*] Waiting for peer to connect on port 5050 ...', 'system');
    appendChat(elBobTranscript, '[*] Connecting to localhost:5050 ...', 'system');

    // Ephemeral Key Agreement simulation (generates 32-byte shared K0)
    state.k0 = randomBytes(32);
    state.active = true;

    // Both parties clone initial ratchet state from K0
    state.alice.outKey = new Uint8Array(state.k0);
    state.alice.inKey = new Uint8Array(state.k0);
    state.alice.sentCount = 0;
    state.alice.recvCount = 0;
    state.alice.outSeq = 1;
    state.alice.inSeq = 1;

    state.bob.outKey = new Uint8Array(state.k0);
    state.bob.inKey = new Uint8Array(state.k0);
    state.bob.sentCount = 0;
    state.bob.recvCount = 0;
    state.bob.outSeq = 1;
    state.bob.inSeq = 1;

    appendChat(elAliceTranscript, '[*] Peer connected. Exchanging public keys ...', 'system');
    appendChat(elBobTranscript, '[*] Peer connected. Exchanging public keys ...', 'system');

    appendChat(elAliceTranscript, '[+] Secure session established. Type your message and press Enter.', 'success');
    appendChat(elBobTranscript, '[+] Secure session established. Type your message and press Enter.', 'success');

    updateUI();
  }

  function endSession() {
    if (!state.active) return;
    state.active = false;

    // Zeroize key material in memory
    if (state.k0) state.k0.fill(0);
    if (state.alice.outKey) state.alice.outKey.fill(0);
    if (state.alice.inKey) state.alice.inKey.fill(0);
    if (state.bob.outKey) state.bob.outKey.fill(0);
    if (state.bob.inKey) state.bob.inKey.fill(0);

    state.k0 = null;
    state.alice.outKey = null;
    state.alice.inKey = null;
    state.bob.outKey = null;
    state.bob.inKey = null;

    appendChat(elAliceTranscript, '[*] Session ended. Key material discarded.', 'system');
    appendChat(elBobTranscript, '[*] Session ended. Key material discarded.', 'system');

    updateUI();
  }

  // --------------------------------------------------------------------------
  // Message Transmission Pipeline
  // --------------------------------------------------------------------------
  async function sendMessage(fromSender, plaintextStr, tamper = false) {
    if (!state.active) {
      appendChat(
        fromSender === 'alice' ? elAliceTranscript : elBobTranscript,
        "[!] No active session. Use 'start --listen' or 'start --connect' first.",
        'error'
      );
      return;
    }

    const isAlice = fromSender === 'alice';
    const senderState = isAlice ? state.alice : state.bob;
    const receiverState = isAlice ? state.bob : state.alice;
    const senderTranscript = isAlice ? elAliceTranscript : elBobTranscript;
    const receiverTranscript = isAlice ? elBobTranscript : elAliceTranscript;

    const seq = senderState.outSeq;
    const nonce = randomBytes(12);
    elInspLastNonce.textContent = toHex(nonce).substring(0, 16) + '...';

    const plaintextBytes = encoder.encode(plaintextStr);

    // 1. Encrypt with current outbound key
    const { ciphertext, tag } = await encryptAESGCM(senderState.outKey, plaintextBytes, nonce);

    // 2. Assemble 30-byte header + ciphertext + 16-byte tag wire envelope
    const header = encodeHeader(seq, nonce, ciphertext.length);
    const envelope = new Uint8Array(HEADER_SIZE + ciphertext.length + TAG_SIZE);
    envelope.set(header, 0);
    envelope.set(ciphertext, HEADER_SIZE);
    envelope.set(tag, HEADER_SIZE + ciphertext.length);

    // 3. Sender displays message and advances outbound ratchet
    appendChat(
      senderTranscript,
      `[you, seq ${seq}] ${plaintextStr}`,
      'outbound',
      {
        seq: seq,
        nonce: nonce,
        ciphertext: ciphertext,
        tag: tag,
        rawEnvelope: envelope,
        tampered: false
      }
    );
    senderState.sentCount++;
    senderState.outSeq++;

    // Key evolution: derive next key and zeroize prior key
    const nextKey = await ratchetDeriveKey(senderState.outKey, nonce);
    senderState.outKey.fill(0); // Zeroize prior key
    senderState.outKey = nextKey;

    // 4. Simulated wire delivery (apply tamper if requested)
    let deliveredEnvelope = new Uint8Array(envelope);
    if (tamper) {
      // Flip one bit inside ciphertext payload
      deliveredEnvelope[HEADER_SIZE + 2] ^= 0xff;
    }

    // 5. Receiver processes incoming envelope
    try {
      const parsed = parseEnvelope(deliveredEnvelope);

      // Check sequence ordering
      if (parsed.seq !== receiverState.inSeq) {
        appendChat(
          receiverTranscript,
          '[!] Unexpected message order detected; message discarded. Session remains active.',
          'error'
        );
        updateUI();
        return;
      }

      // Decrypt and authenticate
      const decrypted = await decryptAESGCM(
        receiverState.inKey,
        parsed.ciphertext,
        parsed.nonce,
        parsed.tag
      );

      // Successful verification
      const decryptedText = decoder.decode(decrypted);
      appendChat(
        receiverTranscript,
        `[peer, seq ${parsed.seq}] ${decryptedText}`,
        'inbound',
        {
          seq: parsed.seq,
          nonce: parsed.nonce,
          ciphertext: parsed.ciphertext,
          tag: parsed.tag,
          rawEnvelope: deliveredEnvelope,
          tampered: false
        }
      );

      receiverState.recvCount++;
      receiverState.inSeq++;

      // Receiver evolves inbound key
      const nextInKey = await ratchetDeriveKey(receiverState.inKey, parsed.nonce);
      receiverState.inKey.fill(0);
      receiverState.inKey = nextInInKey(receiverState, nextInKey);
    } catch (err) {
      // Integrity check failed: fail closed, discard message, preserve session
      const ctLen = deliveredEnvelope.length > HEADER_SIZE + TAG_SIZE ? deliveredEnvelope.length - HEADER_SIZE - TAG_SIZE : 0;
      const parsedNonce = deliveredEnvelope.length >= 26 ? deliveredEnvelope.subarray(14, 26) : new Uint8Array(12);
      const parsedCt = deliveredEnvelope.length >= HEADER_SIZE + ctLen ? deliveredEnvelope.subarray(HEADER_SIZE, HEADER_SIZE + ctLen) : new Uint8Array(0);
      const parsedTag = deliveredEnvelope.length >= HEADER_SIZE + ctLen + TAG_SIZE ? deliveredEnvelope.subarray(HEADER_SIZE + ctLen) : new Uint8Array(TAG_SIZE);

      appendChat(
        receiverTranscript,
        '[!] A message failed integrity verification and was discarded.',
        'error',
        {
          seq: 'Failed Authentication',
          nonce: parsedNonce,
          ciphertext: parsedCt,
          tag: parsedTag,
          rawEnvelope: deliveredEnvelope,
          tampered: true
        }
      );
    }

    updateUI();
  }

  function nextInInKey(recState, nextKey) {
    recState.inKey = nextKey;
    return nextKey;
  }

  // --------------------------------------------------------------------------
  // Event Listeners & Interaction
  // --------------------------------------------------------------------------
  elBtnStart.addEventListener('click', startSession);
  elBtnEnd.addEventListener('click', endSession);

  if (elBtnToggleWire) {
    elBtnToggleWire.addEventListener('click', () => {
      allWireExpanded = !allWireExpanded;
      elBtnToggleWire.textContent = allWireExpanded ? 'Collapse Wire View' : 'Expand Wire View';
      document.querySelectorAll('.wire-details').forEach(d => {
        d.open = allWireExpanded;
      });
    });
  }

  elAliceSend.addEventListener('click', () => {
    const text = elAliceInput.value.trim();
    if (text) {
      sendMessage('alice', text, false);
      elAliceInput.value = '';
    }
  });

  elAliceInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      const text = elAliceInput.value.trim();
      if (text) {
        sendMessage('alice', text, false);
        elAliceInput.value = '';
      }
    }
  });

  elBobSend.addEventListener('click', () => {
    const text = elBobInput.value.trim();
    if (text) {
      sendMessage('bob', text, false);
      elBobInput.value = '';
    }
  });

  elBobInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      const text = elBobInput.value.trim();
      if (text) {
        sendMessage('bob', text, false);
        elBobInput.value = '';
      }
    }
  });

  // Tamper attack simulation
  elBtnTamper.addEventListener('click', () => {
    sendMessage('alice', 'Tampered test payload with flipped ciphertext bit', true);
  });

  // CLI Copy Buttons
  document.querySelectorAll('.cli-copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const cmd = btn.getAttribute('data-cmd');
      if (cmd) {
        navigator.clipboard.writeText(cmd).then(() => {
          const orig = btn.textContent;
          btn.textContent = 'Copied';
          setTimeout(() => {
            btn.textContent = orig;
          }, 1500);
        });
      }
    });
  });

  // --------------------------------------------------------------------------
  // Modal Handlers (Privacy Policy & Terms of Service)
  // --------------------------------------------------------------------------
  const modalBackdrop = document.getElementById('legal-modal');
  const modalTitle = document.getElementById('modal-title');
  const modalBody = document.getElementById('modal-body');
  const btnCloseModal = document.getElementById('modal-close-btn');
  const btnFooterCloseModal = document.getElementById('modal-footer-close-btn');

  const contentPrivacy = `
    <h4>Data Processing Principles</h4>
    <p>The Dynamic Key Evolution (DKE) Hybrid Messaging Engine is local-first software. It establishes direct peer-to-peer TCP transport between two endpoints chosen by the operating users.</p>
    
    <h4>Zero Remote Telemetry</h4>
    <p>The software contains no third-party tracking scripts, analytics SDKs, advertising beacons, or telemetry collectors. No message contents, metadata, sequence numbers, or cryptographic tokens are ever transmitted to any central servers.</p>
    
    <h4>Cryptographic Ephemerality</h4>
    <p>All private keys, session secrets, and message keys exist strictly in volatile process memory. The software never writes private key material or plaintext conversation records to disk storage. When a session terminates, in-memory key buffers are immediately zeroized.</p>
  `;

  const contentTerms = `
    <h4>Open Source License</h4>
    <p>This software is provided under standard open-source terms. The cryptographic implementation is an original engineering contribution designed for reference and production evaluation.</p>
    
    <h4>Permitted Use</h4>
    <p>Users are permitted to inspect, run, modify, and integrate the DKE Messaging Engine in compliance with applicable export controls and open-source licensing terms.</p>
    
    <h4>No Warranty</h4>
    <p>The software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement.</p>
  `;

  function openModal(title, htmlContent) {
    modalTitle.textContent = title;
    modalBody.innerHTML = htmlContent;
    modalBackdrop.classList.add('open');
    btnCloseModal.focus();
  }

  function closeModal() {
    modalBackdrop.classList.remove('open');
  }

  document.querySelectorAll('[data-open-modal]').forEach(trigger => {
    trigger.addEventListener('click', e => {
      e.preventDefault();
      const type = trigger.getAttribute('data-open-modal');
      if (type === 'privacy') {
        openModal('Privacy Policy and Data Practices', contentPrivacy);
      } else if (type === 'terms') {
        openModal('Terms of Service and License', contentTerms);
      }
    });
  });

  btnCloseModal.addEventListener('click', closeModal);
  btnFooterCloseModal.addEventListener('click', closeModal);
  modalBackdrop.addEventListener('click', e => {
    if (e.target === modalBackdrop) closeModal();
  });
  window.addEventListener('keydown', e => {
    if (e.key === 'Escape' && modalBackdrop.classList.contains('open')) {
      closeModal();
    }
  });

  // Initialize UI state
  updateUI();
})();
