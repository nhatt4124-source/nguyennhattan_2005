// Client state variables
const clientId = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
let clientName = '';
let clientKeyPair = null;
let serverPublicKeyPem = '';
let aesKey = null; // CryptoKey object
let eventSource = null;

// Helper: Convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// Helper: Convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Helper: ArrayBuffer to Hex string
function arrayBufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// DOM Elements
const loginModal = document.getElementById('login-modal');
const loginForm = document.getElementById('login-form');
const handshakeLoader = document.getElementById('handshake-loader');
const btnConnect = document.getElementById('btn-connect');
const usernameInput = document.getElementById('username');

const chatWorkspace = document.getElementById('chat-workspace');
const messagesContainer = document.getElementById('messages-container');
const messageInput = document.getElementById('message-input');
const chatForm = document.getElementById('chat-form');
const myNameEl = document.getElementById('my-name');
const myAvatarEl = document.getElementById('my-avatar');
const onlineCountEl = document.getElementById('online-count');
const clientListEl = document.getElementById('client-list');

const securityPanel = document.getElementById('security-panel');
const btnToggleSecurity = document.getElementById('btn-toggle-security');
const btnCloseSecurity = document.getElementById('btn-close-security');
const serverPubkeyPreview = document.getElementById('server-pubkey-preview');
const clientPubkeyPreview = document.getElementById('client-pubkey-preview');
const aesKeyPreview = document.getElementById('aes-key-preview');
const lastPacketPreview = document.getElementById('last-packet-preview');

// Loader steps updating
function updateLoaderStep(stepId, status, errorMsg = '') {
    const stepEl = document.getElementById(stepId);
    if (!stepEl) return;
    
    const iconEl = stepEl.querySelector('.status-icon');
    const textEl = stepEl.querySelector('.step-text');
    
    stepEl.classList.remove('active', 'complete');
    
    if (status === 'active') {
        stepEl.classList.add('active');
        iconEl.textContent = '🔄';
    } else if (status === 'success') {
        stepEl.classList.add('complete');
        iconEl.textContent = '✅';
    } else if (status === 'error') {
        iconEl.textContent = '❌';
        if (errorMsg) textEl.textContent += ` (Lỗi: ${errorMsg})`;
    }
}

// Security toggle
btnToggleSecurity.addEventListener('click', () => {
    securityPanel.classList.toggle('collapsed');
});

btnCloseSecurity.addEventListener('click', () => {
    securityPanel.classList.add('collapsed');
});

// App Startup / Connect Flow
btnConnect.addEventListener('click', async (e) => {
    e.preventDefault();
    const name = usernameInput.value.trim();
    if (!name) {
        alert('Vui lòng nhập tên người dùng!');
        return;
    }
    clientName = name;
    
    // Switch login panel to loader
    loginForm.classList.add('hidden');
    handshakeLoader.classList.remove('hidden');
    
    try {
        // STEP 1: RSA Key Generation
        updateLoaderStep('step-rsa-gen', 'active');
        clientKeyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["encrypt", "decrypt"]
        );
        updateLoaderStep('step-rsa-gen', 'success');
        
        // Export public key to PEM for preview
        const clientPubPem = await exportPublicKeyToPem(clientKeyPair.publicKey);
        clientPubkeyPreview.textContent = clientPubPem;
        
        // STEP 2: Exchanging Public Keys with Server
        updateLoaderStep('step-pubkey-ex', 'active');
        
        // Get server's public key first
        const serverKeyRes = await fetch('/api/server-key');
        if (!serverKeyRes.ok) throw new Error("Không thể lấy public key của server");
        const serverKeyData = await serverKeyRes.json();
        serverPublicKeyPem = serverKeyData.publickey || serverKeyData.public_key;
        serverPubkeyPreview.textContent = serverPublicKeyPem;
        
        // Send client registration
        const regRes = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                client_id: clientId,
                name: clientName,
                public_key: clientPubPem
            })
        });
        
        if (!regRes.ok) {
            const errData = await regRes.json();
            throw new Error(errData.error || "Không thể đăng ký với server");
        }
        
        const regData = await regRes.json();
        const encryptedAesKeyB64 = regData.encrypted_aes_key;
        updateLoaderStep('step-pubkey-ex', 'success');
        
        // STEP 3: Decrypt AES Session Key
        updateLoaderStep('step-aes-decrypt', 'active');
        
        const encryptedAesBuffer = base64ToArrayBuffer(encryptedAesKeyB64);
        const decryptedAesBuffer = await window.crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            clientKeyPair.privateKey,
            encryptedAesBuffer
        );
        
        // Import buffer as AES-CBC key
        aesKey = await window.crypto.subtle.importKey(
            "raw",
            decryptedAesBuffer,
            { name: "AES-CBC" },
            true,
            ["encrypt", "decrypt"]
        );
        
        // Render AES key preview in hex
        const rawAesKeyBuffer = await window.crypto.subtle.exportKey("raw", aesKey);
        aesKeyPreview.textContent = `HEX: ${arrayBufferToHex(rawAesKeyBuffer)}\nSize: 128 bits`;
        updateLoaderStep('step-aes-decrypt', 'success');
        
        // STEP 4: SSE Live Stream Connection
        updateLoaderStep('step-sse-connect', 'active');
        connectSSE();
        
    } catch (err) {
        console.error(err);
        // Find which step failed and mark error
        if (!clientKeyPair) {
            updateLoaderStep('step-rsa-gen', 'error', err.message);
        } else if (!serverPublicKeyPem || !aesKey) {
            updateLoaderStep('step-pubkey-ex', 'error', err.message);
        } else {
            updateLoaderStep('step-sse-connect', 'error', err.message);
        }
    }
});

// Export RSA Public Key to PEM
async function exportPublicKeyToPem(publicKey) {
    const exported = await window.crypto.subtle.exportKey("spki", publicKey);
    const base64 = arrayBufferToBase64(exported);
    return `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
}

// SSE Connection Logic
function connectSSE() {
    eventSource = new EventSource(`/api/stream?client_id=${clientId}`);
    
    eventSource.onopen = () => {
        updateLoaderStep('step-sse-connect', 'success');
        
        // Transition UI from login modal to main workspace
        setTimeout(() => {
            loginModal.classList.add('hidden');
            chatWorkspace.classList.remove('hidden');
            
            // Set user profiles
            myNameEl.textContent = clientName;
            myAvatarEl.textContent = clientName.charAt(0).toUpperCase();
        }, 800);
    };
    
    eventSource.onerror = (e) => {
        console.error("SSE connection error", e);
        if (loginModal.classList.contains('hidden')) {
            // If already inside chat, display connection error in chat window
            appendSystemMessage("Mất kết nối với máy chủ. Đang thử kết nối lại...");
        } else {
            updateLoaderStep('step-sse-connect', 'error', "Không thể kết nối Server-Sent Events stream");
        }
    };
    
    // Handle dynamic client list updates
    eventSource.addEventListener('client_list', (event) => {
        const data = JSON.parse(event.data);
        updateClientList(data.clients);
    });
    
    // Handle decrypted chat messages
    eventSource.addEventListener('chat_message', async (event) => {
        const data = JSON.parse(event.data);
        
        // Display packet in security preview
        lastPacketPreview.textContent = JSON.stringify(data, null, 2);
        
        try {
            // Decrypt message using shared AES key
            const ivBuffer = base64ToArrayBuffer(data.iv);
            const ciphertextBuffer = base64ToArrayBuffer(data.ciphertext);
            
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                {
                    name: "AES-CBC",
                    iv: ivBuffer
                },
                aesKey,
                ciphertextBuffer
            );
            
            const decryptedText = new TextDecoder().decode(decryptedBuffer);
            const messagePacket = JSON.parse(decryptedText);
            
            appendChatMessage(messagePacket.sender_name, messagePacket.message, false, messagePacket.timestamp);
        } catch (err) {
            console.error("Failed to decrypt incoming message:", err);
            appendSystemMessage("⚠️ Nhận được một tin nhắn lỗi hoặc không thể giải mã.");
        }
    });
}

// Update Active Client List in Sidebar
function updateClientList(clients) {
    clientListEl.innerHTML = '';
    
    // Filter out ourselves from the counts and online list
    const otherClients = clients.filter(c => c.id !== clientId);
    onlineCountEl.textContent = otherClients.length;
    
    if (otherClients.length === 0) {
        clientListEl.innerHTML = `<div class="client-placeholder">Không có người dùng nào khác đang trực tuyến.</div>`;
        return;
    }
    
    otherClients.forEach(client => {
        const clientItem = document.createElement('div');
        clientItem.className = 'client-item';
        
        const truncatedId = client.id.substring(0, 10) + '...';
        
        clientItem.innerHTML = `
            <div class="client-avatar">${client.name.charAt(0).toUpperCase()}</div>
            <div class="client-info">
                <div class="client-name-row">
                    <span class="client-name">${client.name}</span>
                    <span class="client-status-dot"></span>
                </div>
                <span class="client-subtext">ID: ${truncatedId}</span>
            </div>
        `;
        
        clientListEl.appendChild(clientItem);
    });
}

// Append Chat Messages to Panel
function appendChatMessage(sender, text, isOutgoing = false, timestamp = null) {
    const time = timestamp ? new Date(timestamp * 1000) : new Date();
    const timeStr = time.toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' });
    
    const wrapper = document.createElement('div');
    wrapper.className = `message-wrapper ${isOutgoing ? 'outgoing' : 'incoming'}`;
    
    wrapper.innerHTML = `
        <span class="msg-sender-name">${isOutgoing ? 'Bạn' : sender}</span>
        <div class="msg-bubble-container">
            <div class="msg-bubble">${escapeHtml(text)}</div>
        </div>
        <span class="msg-meta">
            ${timeStr}
            <span class="msg-lock-indicator" title="Mã hóa AES-128-CBC đầu cuối">
                <svg width="10" height="10" viewBox="0 0 24 24"><path fill="currentColor" d="M12,17A2,2 0 0,0 14,15A2,2 0 0,0 12,13A2,2 0 0,0 10,15A2,2 0 0,0 12,17M18,8A2,2 0 0,1 20,10V20A2,2 0 0,1 18,22H6A2,2 0 0,1 4,20V10C4,8.89 4.9,8 6,8H7V6A5,5 0 0,1 12,1A5,5 0 0,1 17,6V8H18M12,3A3,3 0 0,0 9,6V8H15V6A3,3 0 0,0 12,3Z"/></svg>
                Secure
            </span>
        </span>
    `;
    
    messagesContainer.appendChild(wrapper);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// Append System Messages
function appendSystemMessage(text) {
    const systemEl = document.createElement('div');
    systemEl.className = 'system-message';
    systemEl.textContent = text;
    messagesContainer.appendChild(systemEl);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// Escape HTML utility to prevent XSS
function escapeHtml(unsafe) {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

// Handle Form Submission / Outgoing Messages
chatForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const message = messageInput.value.trim();
    if (!message || !aesKey) return;
    
    messageInput.value = '';
    
    try {
        // 1. Encrypt message locally using shared AES Key
        const encryptedResult = await encryptMessage(aesKey, message);
        
        // Preview the encrypted packet in the security tab
        lastPacketPreview.textContent = JSON.stringify({
            client_id: clientId,
            iv: encryptedResult.iv,
            ciphertext: encryptedResult.ciphertext
        }, null, 2);
        
        // 2. Post encrypted payload to Server
        const response = await fetch('/api/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                client_id: clientId,
                iv: encryptedResult.iv,
                ciphertext: encryptedResult.ciphertext
            })
        });
        
        if (!response.ok) {
            throw new Error("Không thể gửi tin nhắn lên máy chủ");
        }
        
        // 3. Render locally as sent
        appendChatMessage(clientName, message, true);
        
    } catch (err) {
        console.error("Gửi tin nhắn thất bại:", err);
        appendSystemMessage(`⚠️ Gửi tin nhắn thất bại: ${err.message}`);
    }
});

// AES Encrypt Function
async function encryptMessage(key, text) {
    const iv = window.crypto.getRandomValues(new Uint8Array(16));
    const encoded = new TextEncoder().encode(text);
    const ciphertextBuffer = await window.crypto.subtle.encrypt(
        {
            name: "AES-CBC",
            iv: iv
        },
        key,
        encoded
    );
    return {
        iv: arrayBufferToBase64(iv),
        ciphertext: arrayBufferToBase64(ciphertextBuffer)
    };
}
