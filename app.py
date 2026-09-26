import os
import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import bleach
from email import policy
from email.parser import BytesParser
from flask import Flask, g, jsonify, render_template_string, request

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("TEMPMAIL_SECRET_KEY", "change-me-production-secret"),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    TEMPMAIL_DB=os.environ.get("TEMPMAIL_DB", "/tmp/tempmail.db"),
    DOMAIN=os.environ.get("TEMPMAIL_DOMAIN", "buffaloadmin.online"),
    MESSAGE_LIMIT=int(os.environ.get("TEMPMAIL_MAX_MESSAGES", "50")),
    RETENTION_HOURS=int(os.environ.get("TEMPMAIL_RETENTION_HOURS", "24")),
    WEBHOOK_SECRET=os.environ.get("TEMPMAIL_WEBHOOK_SECRET", ""),
    JSON_SORT_KEYS=False,
)

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$"
)
ALLOWED_EMAIL_HTML_TAGS = [
    "a", "b", "blockquote", "br", "code", "div", "em", "h1", "h2", "h3",
    "h4", "h5", "h6", "hr", "i", "img", "li", "ol", "p", "pre", "span",
    "strong", "table", "tbody", "td", "th", "thead", "tr", "u", "ul"
]
ALLOWED_EMAIL_HTML_ATTRIBUTES = {
    "a": ["href", "title"],
    "img": ["src", "alt", "title"],
    "div": ["class", "style"],
    "span": ["class", "style"],
    "p": ["class", "style"],
    "table": ["class", "style"],
    "td": ["class", "style"],
    "th": ["class", "style"],
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db() -> sqlite3.Connection:
    db = getattr(g, "_database", None)
    if db is None:
        db = sqlite3.connect(app.config["TEMPMAIL_DB"])
        db.row_factory = sqlite3.Row
        g._database = db
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            address TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            FOREIGN KEY(token) REFERENCES tokens(token)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            address TEXT NOT NULL,
            sender TEXT NOT NULL,
            subject TEXT,
            recipient TEXT,
            body TEXT,
            html_content TEXT,
            timestamp TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(token) REFERENCES tokens(token),
            FOREIGN KEY(address) REFERENCES addresses(address)
        )
        """
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_emails_address_token ON emails(address, token, expires_at)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_addresses_token ON addresses(token)"
    )
    db.commit()


with app.app_context():
    init_db()

def validate_address(address: str) -> bool:
    if not isinstance(address, str):
        return False
    address = address.strip().lower()
    return bool(EMAIL_PATTERN.fullmatch(address))


def get_auth_token() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()

    header_token = request.headers.get("X-TempMail-Token")
    if header_token:
        return header_token.strip()

    token = request.args.get("token", "").strip()
    if token:
        return token

    return None


def require_token():
    token = get_auth_token()
    if not token:
        return None

    db = get_db()
    row = db.execute("SELECT token FROM tokens WHERE token = ?", (token,)).fetchone()
    if row is None:
        db.execute(
            "INSERT OR REPLACE INTO tokens(token, created_at, last_seen) VALUES (?, ?, ?)",
            (token, now_iso(), now_iso()),
        )
        db.commit()
        return token

    db.execute(
        "UPDATE tokens SET last_seen = ? WHERE token = ?",
        (now_iso(), token),
    )
    db.commit()
    return token


def require_webhook_secret() -> bool:
    secret = app.config["WEBHOOK_SECRET"]
    if not secret:
        return True
    return request.headers.get("X-Webhook-Token") == secret


def parse_email(raw_body):
    if raw_body is None:
        return {
            "subject": "(no subject)",
            "sender": "unknown",
            "recipient": "",
            "text_content": "",
            "html_content": "",
        }

    try:
        if isinstance(raw_body, (bytes, bytearray)):
            message = BytesParser(policy=policy.default).parsebytes(raw_body)
        else:
            message = BytesParser(policy=policy.default).parsestr(str(raw_body))
    except Exception:
        return {
            "subject": "(no subject)",
            "sender": "unknown",
            "recipient": "",
            "text_content": "",
            "html_content": "",
        }

    subject = (message.get("Subject") or "(no subject)").strip()
    sender = (message.get("From") or "unknown").strip()
    recipient = (message.get("To") or "").strip()

    text_content = ""
    html_content = ""

    if message.is_multipart():
        for part in message.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain" and not text_content:
                text_content = part.get_content()
            elif ctype == "text/html" and not html_content:
                html_content = part.get_content()
    else:
        ctype = message.get_content_type()
        if ctype == "text/plain":
            text_content = message.get_content()
        elif ctype == "text/html":
            html_content = message.get_content()

    if html_content:
        html_content = bleach.clean(
            html_content,
            tags=ALLOWED_EMAIL_HTML_TAGS,
            attributes=ALLOWED_EMAIL_HTML_ATTRIBUTES,
            strip=True,
        )

    return {
        "subject": subject,
        "sender": sender,
        "recipient": recipient,
        "text_content": text_content or "Open to view content",
        "html_content": html_content or "",
    }


HTML_PAGE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Inbox</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: { extend: { colors: { brand: { 500: '#3b82f6', 600: '#2563eb' } } } }
        }
    </script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .hide-scrollbar::-webkit-scrollbar { display: none; }
        .hide-scrollbar { -ms-overflow-style: none; scrollbar-width: none; }
        #email-frame { width: 100%; height: 100%; border: none; background: white; }
    </style>
</head>
<body class="bg-gray-50 dark:bg-slate-900 text-slate-800 dark:text-slate-100 min-h-screen flex flex-col transition-colors duration-300 overflow-hidden">
    <div class="bg-white dark:bg-slate-800 p-4 shadow-sm z-20 flex justify-between items-center px-4 safe-area-top">
        <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-full bg-blue-600 text-white flex items-center justify-center font-bold text-lg shadow-lg">B</div>
            <div>
                <h1 class="font-bold text-lg leading-tight">Inbox</h1>
                <p class="text-[10px] text-green-500 font-mono flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span> Secure Mode</p>
            </div>
        </div>
        <div class="flex gap-3">
            <button onclick="toggleTheme()" class="w-10 h-10 rounded-full bg-gray-100 dark:bg-slate-700 flex items-center justify-center transition">
                <i class="fa-solid fa-moon dark:hidden"></i><i class="fa-solid fa-sun hidden dark:block text-yellow-400"></i>
            </button>
            <button onclick="openHistory()" class="relative w-10 h-10 rounded-full bg-gray-100 dark:bg-slate-700 flex items-center justify-center transition">
                <i class="fa-solid fa-clock-rotate-left text-blue-500"></i>
                <span id="total-badge" class="absolute -top-1 -right-1 bg-red-500 text-white text-[10px] min-w-[18px] h-[18px] flex items-center justify-center rounded-full hidden shadow-sm border border-white"></span>
            </button>
        </div>
    </div>

    <div class="flex-1 overflow-y-auto pb-24 px-4 pt-4 hide-scrollbar" id="main-scroll">
        <div class="bg-white dark:bg-slate-800 rounded-2xl p-5 shadow-lg border border-gray-100 dark:border-slate-700 mb-6 relative overflow-hidden group">
            <div class="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 to-indigo-600"></div>
            <div class="flex justify-between items-center mb-2">
                <label class="text-[10px] font-bold text-gray-400 uppercase tracking-wider">Active Address</label>
                <button onclick="generateNewEmail()" class="text-[10px] bg-slate-900 dark:bg-white text-white dark:text-slate-900 px-3 py-1 rounded-full font-bold shadow-md hover:scale-105 transition">New</button>
            </div>
            <div class="flex items-center justify-between bg-gray-50 dark:bg-slate-900 p-3 rounded-xl border border-gray-200 dark:border-slate-700 mb-3 cursor-pointer active:scale-95 transition" onclick="copyEmail()">
                <span id="current-email" class="font-mono text-lg font-semibold text-blue-600 dark:text-blue-400 truncate w-[85%]">Loading...</span>
                <i class="fa-regular fa-copy text-gray-400"></i>
            </div>
            <button onclick="manualRefresh()" class="w-full bg-blue-50 dark:bg-slate-700/50 text-blue-600 dark:text-blue-300 py-2 rounded-lg text-xs font-bold flex items-center justify-center gap-2 transition hover:bg-blue-100 dark:hover:bg-slate-700">
                <i id="refresh-icon" class="fa-solid fa-rotate-right"></i> Check Messages
            </button>
        </div>

        <h2 class="text-xs font-bold text-gray-400 uppercase tracking-widest mb-3 ml-1 flex justify-between">
            Messages <span id="msg-count" class="text-gray-500 bg-gray-200 dark:bg-slate-800 px-2 rounded text-[10px] flex items-center">0</span>
        </h2>

        <div id="inbox" class="space-y-3 pb-10">
            <div class="text-center py-10 opacity-40">
                <i class="fa-regular fa-envelope-open text-5xl mb-3"></i>
                <p class="text-sm">Waiting for emails...</p>
            </div>
        </div>
    </div>

    <div id="read-modal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/80 backdrop-blur-sm transition-opacity" onclick="closeReadModal()"></div>
        <div id="read-content-box" class="absolute bottom-0 left-0 w-full h-[95vh] bg-white dark:bg-slate-900 rounded-t-3xl shadow-2xl flex flex-col transform transition-transform duration-300 translate-y-full">
            <div class="p-4 border-b border-gray-100 dark:border-slate-700 flex justify-between items-center sticky top-0 bg-white/95 dark:bg-slate-900/95 backdrop-blur z-10 rounded-t-3xl">
                <button onclick="closeReadModal()" class="w-8 h-8 rounded-full bg-gray-100 dark:bg-slate-800 flex items-center justify-center hover:bg-gray-200 dark:hover:bg-slate-700 transition"><i class="fa-solid fa-xmark text-sm"></i></button>
                <span class="font-bold text-sm">Full Email View</span>
                <div class="w-8"></div>
            </div>

            <div class="flex-1 overflow-hidden flex flex-col bg-white">
                <div class="p-4 border-b border-gray-100 shrink-0">
                    <h2 id="read-subject" class="text-lg font-bold mb-1 text-slate-800 leading-tight">Subject</h2>
                    <div class="flex items-center gap-2">
                        <div class="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center text-blue-600 font-bold text-xs" id="read-avatar">A</div>
                        <div>
                            <p id="read-sender" class="font-bold text-sm text-slate-700 truncate max-w-[200px]">Sender</p>
                            <p id="read-date" class="text-[10px] text-gray-400">Date</p>
                        </div>
                    </div>
                </div>
                <div class="flex-1 relative w-full bg-white">
                    <iframe id="email-frame" sandbox="allow-same-origin" class="absolute inset-0 w-full h-full"></iframe>
                </div>
            </div>
        </div>
    </div>

    <div id="history-overlay" class="fixed inset-0 z-40 hidden bg-black/50 backdrop-blur-sm transition-opacity opacity-0" onclick="closeHistory()"></div>
    <div id="history-panel" class="fixed bottom-0 left-0 w-full bg-white dark:bg-slate-800 rounded-t-3xl z-50 p-6 shadow-2xl transform translate-y-full transition-transform duration-300 max-h-[75vh] flex flex-col">
        <div class="w-12 h-1.5 bg-gray-300 dark:bg-slate-600 rounded-full mx-auto mb-6"></div>
        <div class="flex justify-between items-center mb-4">
            <h3 class="text-lg font-bold">Switch Account</h3>
            <button onclick="clearHistory()" class="text-red-500 text-xs font-bold uppercase hover:bg-red-50 px-2 py-1 rounded transition">Clear All</button>
        </div>
        <div id="history-list" class="overflow-y-auto space-y-2 flex-1 pr-1 pb-4 hide-scrollbar"></div>
    </div>

    <div id="toast" class="fixed top-6 left-1/2 -translate-x-1/2 bg-slate-800 text-white px-6 py-3 rounded-full shadow-2xl z-[60] flex items-center gap-3 transition-all duration-300 opacity-0 -translate-y-10">
        <span id="toast-msg">OK</span>
    </div>

    <script>
        const DOMAIN = "{{ domain }}";
        let currentEmail = "";
        let emailHistory = JSON.parse(localStorage.getItem("buffalo_hist_v8")) || [];
        let msgCounts = JSON.parse(localStorage.getItem("buffalo_counts_v8")) || {};
        let API_TOKEN = localStorage.getItem("buffalo_token");

        async function ensureToken() {
            if (!API_TOKEN) {
                const res = await fetch('/api/session', { method: 'POST' });
                if (!res.ok) throw new Error('Could not create session');
                const data = await res.json();
                API_TOKEN = data.token;
                localStorage.setItem('buffalo_token', API_TOKEN);
            }
            return API_TOKEN;
        }

        async function init() {
            if (localStorage.getItem('theme') === 'light') document.documentElement.classList.remove('dark');
            await ensureToken();
            const saved = localStorage.getItem('buffalo_active_v8');
            if (saved) {
                switchAccount(saved, false);
            } else {
                generateNewEmail();
            }
            setInterval(() => { if (currentEmail) fetchEmails(true); }, 3000);
        }

        async function generateNewEmail() {
            await ensureToken();
            const res = await fetch('/api/address/new', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${API_TOKEN}`,
                    'Content-Type': 'application/json'
                }
            });
            if (!res.ok) {
                console.error('Failed to create address');
                return;
            }
            const data = await res.json();
            switchAccount(data.address);
            showToast('New address created');
        }

        function switchAccount(email, saveHist = true) {
            currentEmail = email;
            localStorage.setItem('buffalo_active_v8', email);
            document.getElementById('current-email').innerText = email;
            document.getElementById('inbox').innerHTML = `
                <div class="text-center py-20 animate-pulse">
                    <div class="w-16 h-16 bg-blue-100 dark:bg-blue-900/30 rounded-full flex items-center justify-center mx-auto mb-4"><i class="fa-solid fa-satellite-dish text-2xl text-blue-500"></i></div>
                    <p class="font-bold text-blue-500 text-sm">Connecting...</p>
                    <p class="text-sm text-gray-500">Loading inbox</p>
                </div>`;
            document.getElementById('msg-count').innerText = '0';

            if (saveHist) {
                if (!emailHistory.includes(email)) emailHistory.unshift(email);
                if (emailHistory.length > 20) emailHistory.pop();
                localStorage.setItem('buffalo_hist_v8', JSON.stringify(emailHistory));
            }
            closeHistory();
            fetchEmails(false);
        }

        async function fetchEmails(silent = false) {
            if (!currentEmail) return;
            const icon = document.getElementById('refresh-icon');
            if (!silent) icon.classList.add('fa-spin');

            try {
                const res = await fetch(`/api/emails?address=${encodeURIComponent(currentEmail)}`, {
                    headers: {
                        'Authorization': `Bearer ${API_TOKEN}`
                    }
                });

                if (res.status === 401) {
                    await ensureToken();
                    return fetchEmails(silent);
                }

                const data = await res.json();
                if (!Array.isArray(data)) {
                    if (!silent) {
                        document.getElementById('inbox').innerHTML = '<div class="text-center py-10 opacity-40"><i class="fa-regular fa-envelope-open text-5xl mb-3"></i><p class="text-sm">No messages yet</p></div>';
                    }
                    return;
                }

                document.getElementById('msg-count').innerText = data.length;
                msgCounts[currentEmail] = data.length;
                localStorage.setItem('buffalo_counts_v8', JSON.stringify(msgCounts));
                updateHistoryBadges();

                const inbox = document.getElementById('inbox');
                if (data.length > 0) {
                    inbox.innerHTML = data.slice().reverse().map((msg, index) => {
                        const safeSender = msg.sender.replace(/'/g, '&apos;');
                        const safeSubject = msg.subject.replace(/'/g, '&apos;');
                        const safeHtml = encodeURIComponent(msg.html_content || msg.body || '');
                        return `
                            <div onclick="openReadModal('${safeSender}', '${safeSubject}', '${safeHtml}', '${msg.timestamp}')" class="bg-white dark:bg-slate-800 p-4 rounded-2xl shadow-sm border border-gray-100 dark:border-slate-700 relative overflow-hidden group active:scale-[0.98] transition cursor-pointer">
                                <div class="flex justify-between items-start mb-1">
                                    <div class="font-bold text-sm text-slate-800 dark:text-slate-100 truncate w-[70%]">${msg.sender}</div>
                                    <span class="text-[10px] text-gray-400 font-mono">${msg.timestamp}</span>
                                </div>
                                <div class="font-bold text-blue-600 dark:text-blue-400 text-sm mb-1 truncate">${msg.subject}</div>
                                <div class="text-xs text-gray-500 dark:text-slate-400 truncate">Tap to open email</div>
                            </div>`;
                    }).join('');
                } else if (!silent) {
                    inbox.innerHTML = '<div class="text-center py-10 opacity-40"><i class="fa-regular fa-envelope-open text-5xl mb-3"></i><p class="text-sm">No messages yet</p></div>';
                }
            } catch (e) {
                console.error(e);
            }
            if (!silent) setTimeout(() => icon.classList.remove('fa-spin'), 500);
        }

        function openReadModal(sender, subject, encodedHtml, date) {
            const htmlContent = decodeURIComponent(encodedHtml);
            document.getElementById('read-sender').innerText = sender;
            document.getElementById('read-avatar').innerText = sender.charAt(0).toUpperCase();
            document.getElementById('read-subject').innerText = subject;
            document.getElementById('read-date').innerText = date;
            const iframe = document.getElementById('email-frame');
            iframe.srcdoc = htmlContent;
            const modal = document.getElementById('read-modal');
            const box = document.getElementById('read-content-box');
            modal.classList.remove('hidden');
            setTimeout(() => { box.classList.remove('translate-y-full'); }, 10);
        }

        function closeReadModal() {
            const box = document.getElementById('read-content-box');
            box.classList.add('translate-y-full');
            setTimeout(() => { document.getElementById('read-modal').classList.add('hidden'); }, 300);
        }

        function openHistory() {
            updateHistoryBadges();
            const list = document.getElementById('history-list');
            if (emailHistory.length > 0) {
                list.innerHTML = emailHistory.map(email => {
                    const isActive = email === currentEmail;
                    const count = msgCounts[email] || 0;
                    return `
                    <div onclick="switchAccount('${email}')" class="p-3 rounded-xl flex items-center justify-between cursor-pointer transition mb-2 ${isActive ? 'bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-500/30' : 'bg-gray-50 dark:bg-slate-700/50'}">
                        <div class="flex items-center gap-3 overflow-hidden">
                            <div class="w-8 h-8 rounded-full ${isActive ? 'bg-blue-500' : 'bg-gray-300 dark:bg-slate-600'} flex items-center justify-center text-white font-bold text-xs">${email.charAt(0).toUpperCase()}</div>
                            <div class="flex flex-col overflow-hidden"><span class="font-mono text-xs font-bold truncate ${isActive ? 'text-blue-600 dark:text-blue-400' : 'text-gray-700 dark:text-slate-200'}">${email}</span></div>
                        </div>
                        ${count > 0 ? `<span class="bg-red-500 text-white text-[10px] font-bold px-2 py-0.5 rounded-full shadow-sm">${count}</span>` : (isActive ? '<i class="fa-solid fa-check text-blue-500"></i>' : '<i class="fa-solid fa-circle text-gray-300"></i>')}
                    </div>`;
                }).join('');
            } else {
                list.innerHTML = '<p class="text-center text-gray-400 text-sm mt-4">No history</p>';
            }
            document.getElementById('history-overlay').classList.remove('hidden');
            setTimeout(() => {
                document.getElementById('history-overlay').classList.remove('opacity-0');
                document.getElementById('history-panel').classList.remove('translate-y-full');
            }, 10);
        }

        function closeHistory() {
            document.getElementById('history-overlay').classList.add('opacity-0');
            document.getElementById('history-panel').classList.add('translate-y-full');
            setTimeout(() => { document.getElementById('history-overlay').classList.add('hidden'); }, 300);
        }

        function updateHistoryBadges() {
            let total = 0;
            emailHistory.forEach(e => { if (msgCounts[e]) total += msgCounts[e]; });
            const badge = document.getElementById('total-badge');
            if (total > 0) {
                badge.innerText = total > 9 ? '9+' : total;
                badge.classList.remove('hidden');
            } else {
                badge.classList.add('hidden');
            }
        }

        function clearHistory() {
            if (confirm('Clear history?')) {
                emailHistory = [];
                msgCounts = {};
                localStorage.removeItem('buffalo_hist_v8');
                localStorage.removeItem('buffalo_counts_v8');
                closeHistory();
                updateHistoryBadges();
            }
        }

        function manualRefresh() { fetchEmails(); }
        function toggleTheme() {
            if (document.documentElement.classList.contains('dark')) {
                document.documentElement.classList.remove('dark');
                localStorage.setItem('theme', 'light');
            } else {
                document.documentElement.classList.add('dark');
                localStorage.setItem('theme', 'dark');
            }
        }

        function copyEmail() {
            if (!currentEmail) return;
            navigator.clipboard.writeText(currentEmail).then(() => showToast('Copied!'));
        }

        function showToast(msg) {
            const t = document.getElementById('toast');
            document.getElementById('toast-msg').innerText = msg;
            t.classList.remove('opacity-0', '-translate-y-10');
            setTimeout(() => t.classList.add('opacity-0', '-translate-y-10'), 2200);
        }

        init();
    </script>
</body>
</html>
"""


@app.route('/')
def home():
    return render_template_string(HTML_PAGE, domain=app.config["DOMAIN"])


@app.route('/health')
def health():
    return jsonify({"status": "ok", "timestamp": now_iso()}), 200


@app.route('/api/session', methods=['POST'])
def create_session():
    token = str(uuid.uuid4())
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO tokens(token, created_at, last_seen) VALUES (?, ?, ?)",
        (token, now_iso(), now_iso()),
    )
    db.commit()
    return jsonify({"token": token}), 201


@app.route('/api/address/new', methods=['POST'])
def create_address():
    token = require_token()
    if not token:
        return jsonify({"error": "Missing or invalid token"}), 401

    prefix = uuid.uuid4().hex[:12]
    address = f"{prefix}@{app.config['DOMAIN']}".lower()
    db = get_db()
    try:
        db.execute(
            "INSERT INTO addresses(token, address, created_at, last_seen) VALUES (?, ?, ?, ?)",
            (token, address, now_iso(), now_iso()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Address already exists"}), 409

    return jsonify({"address": address, "token": token}), 201


@app.route('/api/emails')
def get_emails():
    token = require_token()
    if not token:
        return jsonify({"error": "Missing or invalid token"}), 401

    target = (request.args.get('address', '') or '').strip().lower()
    if not target or not validate_address(target):
        return jsonify({"error": "Invalid email address"}), 400

    db = get_db()
    address_row = db.execute(
        "SELECT token FROM addresses WHERE address = ? AND token = ?",
        (target, token),
    ).fetchone()

    if address_row is None:
        return jsonify({"error": "Access denied"}), 403

    rows = db.execute(
        """
        SELECT sender, subject, body, html_content, timestamp
        FROM emails
        WHERE address = ? AND token = ? AND expires_at > ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (target, token, now_iso(), app.config['MESSAGE_LIMIT']),
    ).fetchall()

    messages = []
    for row in rows:
        messages.append({
            "sender": row["sender"],
            "subject": row["subject"] or "(no subject)",
            "body": row["body"] or "Open to view content",
            "html_content": row["html_content"] or "",
            "timestamp": row["timestamp"],
        })

    return jsonify(messages), 200


@app.route('/api/webhook', methods=['POST'])
def webhook():
    if not require_webhook_secret():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "Request body required"}), 400

    raw_body = data.get('body') or data.get('raw') or data.get('content') or ''
    parsed = parse_email(raw_body)
    recipient = (data.get('recipient') or parsed.get('recipient') or '').strip().lower()

    if not recipient or not validate_address(recipient):
        return jsonify({"error": "Missing valid recipient"}), 400

    db = get_db()
    row = db.execute(
        "SELECT token FROM addresses WHERE address = ?",
        (recipient,),
    ).fetchone()

    if row is None:
        return jsonify({"status": "ignored", "reason": "unknown recipient"}), 202

    token = row["token"]
    timestamp = datetime.now(timezone.utc).strftime("%H:%M")
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=app.config['RETENTION_HOURS'])).isoformat()

    sender = (data.get('sender') or parsed.get('sender') or 'unknown').strip()
    subject = (data.get('subject') or parsed.get('subject') or '(no subject)').strip()
    body = (data.get('body_text') or parsed.get('text_content') or 'Open to view content').strip()
    html_content = parsed.get('html_content') or ""

    db.execute(
        """
        INSERT INTO emails(token, address, sender, subject, recipient, body, html_content, timestamp, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            token,
            recipient,
            sender,
            subject,
            recipient,
            body,
            html_content,
            timestamp,
            now_iso(),
            expires_at,
        ),
    )
    db.execute(
        "UPDATE addresses SET last_seen = ? WHERE address = ?",
        (now_iso(), recipient),
    )
    db.execute(
        "UPDATE tokens SET last_seen = ? WHERE token = ?",
        (now_iso(), token),
    )
    db.commit()

    return jsonify({"status": "received"}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')), debug=False)
