# 🔐 CipherChat Ultimate

**CipherChat Ultimate** is a zero-knowledge, end-to-end encrypted (E2EE) messaging web and Android application. Every text message, image, video, voice note, document, and peer-to-peer call is encrypted locally on the sender's device using the native **Web Crypto API (ECDH P-256 + AES-256-GCM)** before reaching the server.

🌐 **Live Web App:** [https://cipherchat-1-ceui.onrender.com](https://cipherchat-1-ceui.onrender.com)  
📱 **Mobile App:** Installable directly from the browser as a Progressive Web App (PWA) or packaged as a signed Android `.apk`.

---

## ✨ Key Features

### 🛡️ Cryptography & Privacy
* **End-to-End Encryption (ECDH P-256 + AES-256-GCM):** Asymmetric Elliptic Curve Diffie-Hellman key exchange derives a unique shared AES-256-GCM secret key per conversation. The server only stores unreadable Base64 ciphertexts and Initialization Vectors (IVs).
* **Multi-Device 6-Digit Recovery PIN:** Private keys are encrypted client-side using **PBKDF2 (100,000 iterations)** and a user-defined 6-digit Recovery PIN, enabling seamless chat decryption across multiple phones and laptops.
* **Sealed Sender (Zero-Metadata Mode):** Hides sender identity on the server database (`sender_id = 0`) while embedding the sender's identity inside the encrypted payload.
* **Image Steganography (LSB Pixel Embedding):** Conceals AES-256 encrypted secret messages inside the Least Significant Bits (LSB) of standard PNG images. Recipients can extract and decrypt the hidden message directly inside the chat.
* **60-Digit Safety Number & Color Fingerprint:** Generates a deterministic SHA-256 numeric fingerprint and 8×8 color grid to verify contact encryption keys against Man-in-the-Middle (MITM) interception.
* **Live X-Ray Ciphertext Inspector:** Toggleable X-Ray mode lets users inspect raw encrypted database payloads and metadata in real time.

### 💬 Messaging & Media
* **Encrypted Direct Messages & Group Chats:** Create private E2EE groups where a shared AES-256 group key is individually wrapped for each member.
* **Full Media Support with Live Progress & Cancel:** Send encrypted photos, videos, voice notes, and documents (up to 20 MB) with a circular SVG upload progress ring, live percentage counter, and instant **Cancel (`✕`)** support.
* **Interactive Chat Actions:** Reply with quotes, forward re-encrypted messages across chats/groups, edit sent messages, react with emojis, and create live encrypted polls.
* **Self-Destructing Messages & View-Once Media:** Configure disappearing message timers (`15s`, `1m`, `24h`) or send View-Once photos/videos that permanently wipe upon closing.
* **Full-Screen Lightbox Viewer:** Tap any image or video in chat to view it in a full-screen lightbox with one-click device download.

### 📞 Real-Time Calls & Security Controls
* **Full-Screen WebRTC Audio, Video & Screen Sharing:** Peer-to-peer DTLS-SRTP encrypted voice/video calls with screen sharing and a touch/mouse draggable self-view camera window (PiP).
* **App Screen Lock & Decoy (Duress) PIN:** Idle auto-lock screen with a secondary Decoy PIN that opens an empty safe-mode workspace under coercion.
* **Encrypted `.cipher` Vault Backup & Restore:** Export and import local encryption keys and message archives into a PIN-encrypted `.cipher` file.
* **Administrator Control Panel:** Dedicated admin dashboard to monitor registered users, cloud database storage usage, and review user-submitted account deletion requests backed by mandatory Terms & Conditions consent audit logs.

---

## 🛠️ Tech Stack

| Layer | Technology |
| :--- | :--- |
| **Backend** | Node.js (v22+) Native HTTP, Crypto, TLS & Zlib Modules |
| **Database** | Neon Cloud PostgreSQL (`pg`) with Automatic Local SQLite (`node:sqlite`) Fallback |
| **Frontend** | HTML5, Tailwind CSS, Vanilla JavaScript (ES2023) |
| **Security & Calling** | Web Crypto API (`ECDH`, `AES-GCM`, `PBKDF2`, `SHA-256`), WebRTC (`RTCPeerConnection`) |
| **Email OTP Delivery** | Brevo Transactional Email API (HTTPS) + Gmail SMTP Fallback |
| **Mobile Packaging** | Progressive Web App (Manifest + Service Worker) & PWABuilder Android `.apk` |

---

## 📖 How to Use CipherChat

1. **Create an Account:**
   * Open [https://cipherchat-1-ceui.onrender.com](https://cipherchat-1-ceui.onrender.com) and switch to **Create Account**.
   * Enter your Full Name, unique `@username`, 10-digit Mobile Number, Email Address, and a **6-Digit E2EE Recovery PIN**.
   * Verify the 6-digit OTP sent to your email. Your session remains logged in across app restarts until you explicitly tap **Exit**.
2. **Connect with Friends:**
   * Click **+ Add / QR Invite** in the sidebar.
   * Search by `@username`, mobile number, or email, or switch to **My QR & Invite Link** to generate a temporary 1-hour invite link/code (`CC-XXXXXX`) without sharing personal contact details.
3. **Send Encrypted Messages, Stego Photos & Calls:**
   * Select a friend or group to start chatting.
   * Tap **`+`** in the message bar to attach files, embed secret text inside an image (**Steganography**), create an **Encrypted Poll**, or toggle **Sealed Sender**, **View-Once**, and **Self-Destruct Timers**.
   * Use the top header icons (**📞** / **📹**) to start an encrypted call or share your screen.
4. **Backup & Storage Monitoring:**
   * Open **Settings (`⚙`)** to view live Neon PostgreSQL storage usage (`MB / 512 MB`), configure **App Lock / Decoy PIN**, manage active device sessions, or download a `.cipher` vault backup.

---

## 💻 Local Setup & Cloud Deployment

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/arpitshakya12/cipherchat.git
cd cipherchat
npm install
```

### 2. Configure Environment Variables
Create a `.env` file in the root directory (do not commit `.env` to GitHub):
```env
PORT=3000
DATABASE_URL=postgresql://user:password@host/dbname?sslmode=require
BREVO_API_KEY=xkeysib-your-brevo-api-key
SENDER_EMAIL=your-verified-sender@gmail.com
ADMIN_EMAIL=navodayanarpit12@gmail.com
```
*(If `DATABASE_URL` is omitted locally, the server automatically creates a local `cipherchat.db` SQLite database.)*

### 3. Run Locally
```bash
node --env-file=.env server.js
```
Open `http://localhost:3000` in your browser.

---

## 👨‍💻 Developer

**Arpit Shakya**  
* GitHub: [@arpitshakya12](https://github.com/arpitshakya12)  
* Email: `navodayanarpit12@gmail.com`
