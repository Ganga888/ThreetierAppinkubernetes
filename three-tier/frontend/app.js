// app.js
const API_BASE = (location.hostname === 'localhost' || location.hostname === '127.0.0.1')
  ? 'http://localhost:8080'   // local dev backend
  : '/api';                   // production behind Ingress /api -> backend

function show(id, text, ok = false) {
  const el = document.getElementById(id);
  el.style.color = ok ? 'green' : '#d9534f';
  el.textContent = text;
}

async function postJSON(path, payload) {
  const res = await fetch(API_BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    credentials: 'include'
  });
  return res.json();
}

/* Signup handler */
const signupForm = document.getElementById('signupForm');
if (signupForm) {
  signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('signupUsername').value.trim();
    const password = document.getElementById('signupPassword').value;
    if (!username || !password) { show('signupMsg', 'Username and password required'); return; }
    try {
      const data = await postJSON('/signup', { username, password });
      if (data.success) {
        show('signupMsg', 'Account created ✓. Redirecting to login...', true);
        setTimeout(() => location.href = 'index.html', 1200);
      } else {
        show('signupMsg', data.message || 'Signup failed');
      }
    } catch (err) {
      show('signupMsg', 'Network error: ' + err.message);
    }
  });
}

/* Login handler */
const loginForm = document.getElementById('loginForm');
if (loginForm) {
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    if (!username || !password) { show('loginMsg', 'Username and password required'); return; }
    try {
      const data = await postJSON('/login', { username, password });
      if (data.success) {
        // store token and redirect or show dashboard
        if (data.token) localStorage.setItem('jwt', data.token);
        show('loginMsg', 'Login success ✓', true);
        setTimeout(() => alert('Logged in — token stored in localStorage'), 500);
      } else {
        show('loginMsg', data.message || 'Invalid credentials');
      }
    } catch (err) {
      show('loginMsg', 'Network error: ' + err.message);
    }
  });
}