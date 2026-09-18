/**
 * Universal GitHub Gist Sync Module
 * Zero plaintext persistence (Web Crypto API + IndexedDB).
 * Zero-knowledge remote encryption for Gist sync.
 */
class GitHubSyncModule {
  constructor() {
    // Volatile RAM Session Context - Overwritten & Purged on Disconnect
    this.session = {
      token: null,
      gistId: null,
      cryptoKey: null,
    };

    this.state = 'DISCONNECTED'; // DISCONNECTED, CONNECTING, CONNECTED, ERROR, LOCKED
    this.dbName = 'UniversalGistSyncDB';
    this.storeName = 'auth_profile';
    this.listeners = new Map();
    this.uiInitialized = false;

    // Gist filename used to isolate client-encrypted payload
    this.syncFileName = 'secure_sync_store.json.enc';
  }

  /* -------------------------------------------------------------------------
   * Public Event Emitter Pattern
   * ------------------------------------------------------------------------- */
  on(eventName, callback) {
    if (!this.listeners.has(eventName)) {
      this.listeners.set(eventName, []);
    }
    this.listeners.get(eventName).push(callback);
  }

  emit(eventName, data) {
    if (this.listeners.has(eventName)) {
      this.listeners.get(eventName).forEach((cb) => {
        try {
          cb(data);
        } catch (e) {
          console.error(`Error in event listener for ${eventName}:`, e);
        }
      });
    }
  }

  setState(newState, meta = null) {
    this.state = newState;
    this.updateBadgeUI();
    this.emit('stateChange', { state: newState, meta });
  }

  /* -------------------------------------------------------------------------
   * Cryptographic Utilities (Web Crypto API - PBKDF2 / AES-GCM 256)
   * ------------------------------------------------------------------------- */
  async _deriveKey(passphrase, saltBuffer) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async _encryptText(plaintext, cryptoKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      encoded
    );

    return {
      iv: Array.from(iv),
      ciphertext: Array.from(new Uint8Array(ciphertext)),
    };
  }

  async _decryptText(cipherObj, cryptoKey) {
    const iv = new Uint8Array(cipherObj.iv);
    const data = new Uint8Array(cipherObj.ciphertext);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      data
    );

    return new TextDecoder().decode(decrypted);
  }

  /* -------------------------------------------------------------------------
   * IndexedDB Management (Encrypted Vault)
   * ------------------------------------------------------------------------- */
  _openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.dbName, 1);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName, { keyPath: 'id' });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async _getStoredProfile() {
    const db = await this._openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.storeName, 'readonly');
      const req = tx.objectStore(this.storeName).get('main_profile');
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }

  async _saveStoredProfile(profile) {
    const db = await this._openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.storeName, 'readwrite');
      const req = tx.objectStore(this.storeName).put({ id: 'main_profile', ...profile });
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async _deleteStoredProfile() {
    const db = await this._openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.storeName, 'readwrite');
      const req = tx.objectStore(this.storeName).delete('main_profile');
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  /* -------------------------------------------------------------------------
   * RAM Lifecycle & Hygiene
   * ------------------------------------------------------------------------- */
  _wipeRAM() {
    if (this.session.token) {
      this.session.token = '0'.repeat(this.session.token.length);
    }
    if (this.session.gistId) {
      this.session.gistId = '0'.repeat(this.session.gistId.length);
    }
    this.session.token = null;
    this.session.gistId = null;
    this.session.cryptoKey = null;
  }

  /* -------------------------------------------------------------------------
   * Initialization & Auto-Detection
   * ------------------------------------------------------------------------- */
  async init(options = {}) {
    if (options.syncFileName) {
      this.syncFileName = options.syncFileName;
    }

    this._injectUI();

    try {
      const stored = await this._getStoredProfile();
      if (stored && stored.salt && stored.encryptedPayload) {
        this.setState('LOCKED');
      } else {
        this.setState('DISCONNECTED');
      }
    } catch (err) {
      this.setState('ERROR', err.message);
      this.emit('error', err);
    }
  }

  /* -------------------------------------------------------------------------
   * Connection Handlers
   * ------------------------------------------------------------------------- */
  async connect() {
    const stored = await this._getStoredProfile();
    if (!stored) {
      this._showSetupModal();
      return;
    }

    if (this.state === 'LOCKED' || this.state === 'DISCONNECTED') {
      this._showUnlockModal();
    }
  }

  async disconnect() {
    this._wipeRAM();
    this.setState('DISCONNECTED');
    this.emit('syncComplete', { action: 'disconnect', success: true });
  }

  async purgeCredentials() {
    this._wipeRAM();
    await this._deleteStoredProfile();
    this.setState('DISCONNECTED');
  }

  /* -------------------------------------------------------------------------
   * GitHub API Core Operations
   * ------------------------------------------------------------------------- */
  async _verifyAndSyncGist() {
    this.setState('CONNECTING');
    try {
      const res = await fetch(`https://api.github.com/gists/${this.session.gistId}`, {
        headers: {
          Authorization: `token ${this.session.token}`,
          Accept: 'application/vnd.github.v3+json',
        },
      });

      if (!res.ok) {
        throw new Error(`GitHub Gist API responded with status: ${res.status}`);
      }

      this.setState('CONNECTED');
      // Automatic download and decryption sync
      const remoteData = await this.downloadData();
      this.emit('syncComplete', { action: 'initialSync', data: remoteData });
    } catch (err) {
      this.setState('ERROR', err.message);
      this.emit('error', err);
    }
  }

  async createNewGist(token) {
    const payload = {
      description: 'Universal Encrypted Data Vault',
      public: false,
      files: {
        [this.syncFileName]: {
          content: JSON.stringify({ init: true, timestamp: Date.now() }),
        },
      },
    };

    const res = await fetch('https://api.github.com/gists', {
      method: 'POST',
      headers: {
        Authorization: `token ${token}`,
        Accept: 'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.message || `Failed to create secret Gist (${res.status})`);
    }

    const json = await res.json();
    return json.id;
  }

  async uploadData(content, mode = 'replace') {
    if (this.state !== 'CONNECTED') {
      throw new Error('Module must be CONNECTED to upload data.');
    }

    let payloadString = typeof content === 'string' ? content : JSON.stringify(content);

    if (mode === 'append') {
      const existing = (await this.downloadData()) || '';
      payloadString = existing + (existing.length ? '\n' : '') + payloadString;
    }

    // Encrypt client-side using the master derived key
    const encrypted = await this._encryptText(payloadString, this.session.cryptoKey);

    const patchBody = {
      files: {
        [this.syncFileName]: {
          content: JSON.stringify(encrypted),
        },
      },
    };

    const res = await fetch(`https://api.github.com/gists/${this.session.gistId}`, {
      method: 'PATCH',
      headers: {
        Authorization: `token ${this.session.token}`,
        Accept: 'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(patchBody),
    });

    if (!res.ok) {
      throw new Error(`Upload failed with status code ${res.status}`);
    }

    this.emit('syncComplete', { action: 'upload', mode, data: payloadString });
    return payloadString;
  }

  async downloadData() {
    if (!this.session.token || !this.session.gistId || !this.session.cryptoKey) {
      throw new Error('Session credentials uninitialized in volatile memory.');
    }

    const res = await fetch(`https://api.github.com/gists/${this.session.gistId}`, {
      headers: {
        Authorization: `token ${this.session.token}`,
        Accept: 'application/vnd.github.v3+json',
      },
      cache: 'no-store',
    });

    if (!res.ok) {
      throw new Error(`Failed to pull remote gist (${res.status})`);
    }

    const gist = await res.json();
    const file = gist.files[this.syncFileName];

    if (!file || !file.content) {
      return '';
    }

    try {
      const parsedCipher = JSON.parse(file.content);
      if (parsedCipher.init) return ''; // Initial placeholder
      return await this._decryptText(parsedCipher, this.session.cryptoKey);
    } catch (e) {
      throw new Error('Payload decryption failed: incorrect key or corrupted remote Gist.');
    }
  }

  /* -------------------------------------------------------------------------
   * Interactive UI, Badges & Modals Injection
   * ------------------------------------------------------------------------- */
  _injectUI() {
    if (this.uiInitialized) return;

    // 1. Status Indicator Badge
    const badge = document.createElement('div');
    badge.className = 'gh-sync-badge';
    badge.id = 'gh-sync-badge-element';
    badge.setAttribute('data-state', this.state);
    badge.innerHTML = `
      <div class="gh-sync-dot"></div>
      <span class="gh-sync-label">Sync Offline</span>
    `;
    badge.onclick = () => this._handleBadgeClick();
    document.body.appendChild(badge);

    // 2. Modals Container
    const modalHost = document.createElement('div');
    modalHost.id = 'gh-sync-modal-host';
    document.body.appendChild(modalHost);

    this.uiInitialized = true;
  }

  updateBadgeUI() {
    const badge = document.getElementById('gh-sync-badge-element');
    if (!badge) return;

    badge.setAttribute('data-state', this.state);
    const label = badge.querySelector('.gh-sync-label');

    switch (this.state) {
      case 'DISCONNECTED':
        label.textContent = 'Disconnected';
        break;
      case 'CONNECTING':
        label.textContent = 'Connecting...';
        break;
      case 'CONNECTED':
        label.textContent = 'Connected';
        break;
      case 'ERROR':
        label.textContent = 'Sync Error';
        break;
      case 'LOCKED':
        label.textContent = 'Locked (Decrypt)';
        break;
    }
  }

  _handleBadgeClick() {
    if (this.state === 'CONNECTED') {
      this._showConnectedMenuModal();
    } else if (this.state === 'LOCKED' || this.state === 'DISCONNECTED') {
      this.connect();
    } else if (this.state === 'ERROR') {
      this.connect();
    }
  }

  _closeModal() {
    const host = document.getElementById('gh-sync-modal-host');
    if (host) host.innerHTML = '';
  }

  _showSetupModal() {
    const host = document.getElementById('gh-sync-modal-host');
    host.innerHTML = `
      <div class="gh-sync-modal-overlay active">
        <div class="gh-sync-modal">
          <h3>Setup GitHub Sync</h3>
          <p>Credentials will be encrypted with your passphrase and stored locally in IndexedDB.</p>
          
          <div class="gh-sync-form-group">
            <label>GitHub Personal Access Token (Classic - "gist" scope)</label>
            <input type="password" id="gh-setup-token" class="gh-sync-input" placeholder="ghp_xxxxxxxxxxxx" autocomplete="off" />
          </div>

          <div class="gh-sync-form-group">
            <label>Secret Gist ID (Optional)</label>
            <div style="display: flex; gap: 8px;">
              <input type="text" id="gh-setup-gist" class="gh-sync-input" placeholder="Leave empty to auto-create" />
              <button type="button" id="gh-btn-create-gist" class="gh-sync-btn gh-sync-btn-secondary" style="white-space: nowrap;">Create Gist</button>
            </div>
          </div>

          <div class="gh-sync-form-group">
            <label>Master Encryption Passphrase</label>
            <input type="password" id="gh-setup-pass" class="gh-sync-input" placeholder="Strong local encryption passphrase" autocomplete="off" />
          </div>

          <div class="gh-sync-btn-row">
            <button type="button" class="gh-sync-btn gh-sync-btn-secondary" id="gh-setup-cancel">Cancel</button>
            <button type="button" class="gh-sync-btn gh-sync-btn-primary" id="gh-setup-save">Save & Connect</button>
          </div>
        </div>
      </div>
    `;

    document.getElementById('gh-setup-cancel').onclick = () => this._closeModal();

    // Create New Gist workflow button
    document.getElementById('gh-btn-create-gist').onclick = async () => {
      const token = document.getElementById('gh-setup-token').value.trim();
      if (!token) {
        alert('Please enter your GitHub Personal Access Token first.');
        return;
      }

      try {
        const btn = document.getElementById('gh-btn-create-gist');
        btn.textContent = 'Creating...';
        btn.disabled = true;

        const newId = await this.createNewGist(token);
        document.getElementById('gh-setup-gist').value = newId;
        this._showOneTimeGistModal(newId);
      } catch (e) {
        alert('Gist Creation Error: ' + e.message);
      } finally {
        const btn = document.getElementById('gh-btn-create-gist');
        if (btn) {
          btn.textContent = 'Create Gist';
          btn.disabled = false;
        }
      }
    };

    document.getElementById('gh-setup-save').onclick = async () => {
      const token = document.getElementById('gh-setup-token').value.trim();
      let gistId = document.getElementById('gh-setup-gist').value.trim();
      const pass = document.getElementById('gh-setup-pass').value;

      if (!token || !pass) {
        alert('GitHub Token and Master Passphrase are required.');
        return;
      }

      try {
        if (!gistId) {
          gistId = await this.createNewGist(token);
          this._showOneTimeGistModal(gistId);
        }

        // Generate Salt and derive Encryption Key
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await this._deriveKey(pass, salt);

        // Encrypt credentials together
        const payloadToEncrypt = JSON.stringify({ token, gistId });
        const encData = await this._encryptText(payloadToEncrypt, key);

        // Save salt + ciphertext to IndexedDB (No Plaintext)
        await this._saveStoredProfile({
          salt: Array.from(salt),
          encryptedPayload: encData,
        });

        // Store into volatile RAM session
        this.session.token = token;
        this.session.gistId = gistId;
        this.session.cryptoKey = key;

        this._closeModal();
        await this._verifyAndSyncGist();
      } catch (e) {
        alert('Setup failed: ' + e.message);
      }
    };
  }

  _showOneTimeGistModal(gistId) {
    const existingModal = document.querySelector('.gh-sync-modal-overlay.active');
    if (existingModal) existingModal.style.visibility = 'hidden';

    const overlay = document.createElement('div');
    overlay.className = 'gh-sync-modal-overlay active';
    overlay.style.zIndex = '10002';
    overlay.innerHTML = `
      <div class="gh-sync-modal">
        <h3>Gist Created Successfully</h3>
        <p>This is your newly initialized Secret Gist ID. Save this ID in a safe place. It will only be shown once in this view.</p>
        <div class="gh-sync-code-box" id="gh-new-gist-display">${gistId}</div>
        <div class="gh-sync-btn-row">
          <button type="button" class="gh-sync-btn gh-sync-btn-secondary" id="gh-copy-gist-btn">Copy to Clipboard</button>
          <button type="button" class="gh-sync-btn gh-sync-btn-primary" id="gh-dismiss-gist-btn">I Have Saved It</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    overlay.querySelector('#gh-copy-gist-btn').onclick = () => {
      navigator.clipboard.writeText(gistId);
      overlay.querySelector('#gh-copy-gist-btn').textContent = 'Copied!';
    };

    overlay.querySelector('#gh-dismiss-gist-btn').onclick = () => {
      // Overwrite sensitive element text before removing
      overlay.querySelector('#gh-new-gist-display').textContent = '';
      overlay.remove();
      if (existingModal) existingModal.style.visibility = 'visible';
    };
  }

  _showUnlockModal() {
    const host = document.getElementById('gh-sync-modal-host');
    host.innerHTML = `
      <div class="gh-sync-modal-overlay active">
        <div class="gh-sync-modal">
          <h3>Unlock Encrypted Vault</h3>
          <p>Enter your Master Encryption Passphrase to decrypt credentials directly into volatile RAM.</p>
          
          <div class="gh-sync-form-group">
            <label>Master Encryption Passphrase</label>
            <input type="password" id="gh-unlock-pass" class="gh-sync-input" autocomplete="off" />
          </div>

          <div class="gh-sync-btn-row">
            <button type="button" class="gh-sync-btn gh-sync-btn-secondary" id="gh-unlock-cancel">Cancel</button>
            <button type="button" class="gh-sync-btn gh-sync-btn-primary" id="gh-unlock-btn">Unlock & Connect</button>
          </div>
        </div>
      </div>
    `;

    document.getElementById('gh-unlock-cancel').onclick = () => this._closeModal();

    const doUnlock = async () => {
      const pass = document.getElementById('gh-unlock-pass').value;
      if (!pass) return;

      try {
        const stored = await this._getStoredProfile();
        if (!stored) throw new Error('No configuration profile found.');

        const salt = new Uint8Array(stored.salt);
        const derivedKey = await this._deriveKey(pass, salt);

        // Decrypt profile
        const decryptedStr = await this._decryptText(stored.encryptedPayload, derivedKey);
        const creds = JSON.parse(decryptedStr);

        // Populate volatile RAM session exclusively
        this.session.token = creds.token;
        this.session.gistId = creds.gistId;
        this.session.cryptoKey = derivedKey;

        this._closeModal();
        await this._verifyAndSyncGist();
      } catch (e) {
        alert('Authentication failed: Invalid Passphrase or Decryption Error.');
      }
    };

    document.getElementById('gh-unlock-btn').onclick = doUnlock;
    document.getElementById('gh-unlock-pass').onkeydown = (e) => {
      if (e.key === 'Enter') doUnlock();
    };
  }

  _showConnectedMenuModal() {
    const host = document.getElementById('gh-sync-modal-host');
    host.innerHTML = `
      <div class="gh-sync-modal-overlay active">
        <div class="gh-sync-modal">
          <h3>Connection Session Active</h3>
          <p>Your sync session is unlocked and maintained in volatile memory.</p>
          <div style="margin: 16px 0; font-size: 13px;">
            <div><strong>Active Gist ID:</strong> <span style="font-family: monospace;">${this.session.gistId || 'N/A'}</span></div>
          </div>
          <div class="gh-sync-btn-row">
            <button type="button" class="gh-sync-btn gh-sync-btn-secondary" id="gh-session-close">Close</button>
            <button type="button" class="gh-sync-btn gh-sync-btn-danger" id="gh-session-disconnect">Disconnect & Purge RAM</button>
          </div>
        </div>
      </div>
    `;

    document.getElementById('gh-session-close').onclick = () => this._closeModal();
    document.getElementById('gh-session-disconnect').onclick = () => {
      this.disconnect();
      this._closeModal();
    };
  }

  promptUploadChoice(contentToUpload) {
    return new Promise((resolve) => {
      const host = document.getElementById('gh-sync-modal-host');
      host.innerHTML = `
        <div class="gh-sync-modal-overlay active">
          <div class="gh-sync-modal">
            <h3>Commit Data to Cloud</h3>
            <p>Select how you wish to synchronize your content with the encrypted remote Gist.</p>
            <div class="gh-sync-btn-row">
              <button type="button" class="gh-sync-btn gh-sync-btn-secondary" id="gh-choice-cancel">Cancel</button>
              <button type="button" class="gh-sync-btn gh-sync-btn-secondary" id="gh-choice-append">Append Content</button>
              <button type="button" class="gh-sync-btn gh-sync-btn-primary" id="gh-choice-replace">Replace / Overwrite</button>
            </div>
          </div>
        </div>
      `;

      document.getElementById('gh-choice-cancel').onclick = () => {
        this._closeModal();
        resolve(null);
      };

      document.getElementById('gh-choice-append').onclick = async () => {
        this._closeModal();
        const res = await this.uploadData(contentToUpload, 'append');
        resolve(res);
      };

      document.getElementById('gh-choice-replace').onclick = async () => {
        this._closeModal();
        const res = await this.uploadData(contentToUpload, 'replace');
        resolve(res);
      };
    });
  }
}

// Attach to window for drop-in browser usage
window.GitHubSyncModule = GitHubSyncModule;