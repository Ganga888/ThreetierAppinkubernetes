# Three-tier Microservice App on Kops (ganga888.online)

All-in-one guide with **full code**, **Dockerfiles**, **Kubernetes manifests**, and **kubectl step-by-step commands** to build, push, and deploy a secure three-tier app (Frontend → Backend → Postgres) on your kOps AWS cluster using domain `ganga888.online`.

---

## Project structure

```
three-tier/
├─ frontend/
│  ├ index.html
│  ├ signup.html
│  ├ styles.css
│  ├ app.js
│  └ Dockerfile
├─ backend/
│  ├ package.json
│  ├ package-lock.json  # optional
│  ├ app.js
│  ├ .env.example
│  └ Dockerfile
├─ k8s/
│  ├ postgres-pvc.yaml
│  ├ postgres-deployment.yaml
│  ├ backend-deployment.yaml
│  ├ frontend-deployment.yaml
│  ├ app-ingress.yaml
│  └ cluster-issuer-staging.yaml
└ README.md  # this document
```

---

# 1. Frontend — files

Create folder `three-tier/frontend` and add these files exactly.

### index.html
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>App — Login</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <link rel="stylesheet" href="styles.css" />
</head>
<body>
  <main class="card">
    <h1>Login</h1>
    <form id="loginForm">
      <label>Username</label>
      <input id="loginUsername" required />
      <label>Password</label>
      <input id="loginPassword" type="password" required />
      <button type="submit">Login</button>
    </form>

    <div class="links">
      <a href="signup.html">Create an account</a>
    </div>

    <div id="loginMsg" class="msg"></div>
  </main>

  <script src="app.js"></script>
</body>
</html>
```

### signup.html
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>App — Signup</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <link rel="stylesheet" href="styles.css" />
</head>
<body>
  <main class="card">
    <h1>Sign up</h1>
    <form id="signupForm">
      <label>Username</label>
      <input id="signupUsername" required />
      <label>Password</label>
      <input id="signupPassword" type="password" required />
      <button type="submit">Sign up</button>
    </form>

    <div class="links">
      <a href="index.html">Already have an account? Login</a>
    </div>

    <div id="signupMsg" class="msg"></div>
  </main>

  <script src="app.js"></script>
</body>
</html>
```

### styles.css
```css
:root { font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#f5f7fb; }
.card { width: 320px; padding:20px; border-radius:8px; background:#fff; box-shadow:0 6px 18px rgba(0,0,0,0.06); }
h1 { margin: 0 0 12px 0; font-size:22px; }
label { display:block; margin-top:10px; font-size:13px; color:#555; }
input { width:100%; padding:8px 10px; border-radius:6px; border:1px solid #e2e8f0; margin-top:6px; box-sizing:border-box; }
button { margin-top:16px; width:100%; padding:10px; border-radius:6px; border:0; background:#2563eb; color:white; font-weight:600; cursor:pointer; }
.links { margin-top:12px; font-size:13px; text-align:center; }
.msg { margin-top:12px; color:#d9534f; font-size:13px; min-height:18px; }
```

### app.js
```javascript
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
```

### Dockerfile (frontend)
Create `three-tier/frontend/Dockerfile`:
```dockerfile
FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
```

---

# 2. Backend — code (bcrypt + JWT + Postgres)
Create folder `three-tier/backend` and add files below.

### package.json
```json
{
  "name": "three-tier-backend",
  "version": "1.0.0",
  "main": "app.js",
  "scripts": { "start": "node app.js" },
  "dependencies": {
    "bcrypt": "^5.1.0",
    "body-parser": "^1.20.2",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "pg": "^8.11.0"
  }
}
```

### .env.example
```
PORT=8080
DB_HOST=postgres
DB_PORT=5432
DB_USER=postgres
DB_PASS=change_me
DB_NAME=myapp
JWT_SECRET=please_change_this_to_a_strong_secret
JWT_EXPIRES_IN=1h
```

### app.js
```js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg');

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'please_change';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

const pool = new Pool({
  host: process.env.DB_HOST || 'postgres',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASS || 'change_me',
  database: process.env.DB_NAME || 'myapp',
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

async function ensureSchema() {
  const client = await pool.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    console.log("Ensured users table exists");
  } finally {
    client.release();
  }
}

const app = express();
app.use(bodyParser.json());
app.use(cors({ origin: true, credentials: true }));

// Health
app.get('/health', (req, res) => res.json({ ok: true }));

// Signup
app.post('/api/signup', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ success: false, message: 'username & password required' });

  try {
    const hash = await bcrypt.hash(password, 10);
    const q = 'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, created_at';
    const r = await pool.query(q, [username, hash]);
    const user = r.rows[0];
    res.json({ success: true, user: { id: user.id, username: user.username } });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ success: false, message: 'username already exists' });
    console.error(err);
    res.status(500).json({ success: false, message: 'internal error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ success: false, message: 'username & password required' });

  try {
    const q = 'SELECT id, username, password_hash FROM users WHERE username = $1';
    const r = await pool.query(q, [username]);
    if (r.rowCount === 0) return res.status(401).json({ success: false, message: 'invalid credentials' });

    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ success: false, message: 'invalid credentials' });

    const token = jwt.sign({ sub: user.id, username: user.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    res.json({ success: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'internal error' });
  }
});

// Protected example
app.get('/api/profile', async (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'missing token' });
    const token = auth.slice(7);
    const payload = jwt.verify(token, JWT_SECRET);
    const q = 'SELECT id, username, created_at FROM users WHERE id = $1';
    const r = await pool.query(q, [payload.sub]);
    if (r.rowCount === 0) return res.status(404).json({ success: false, message: 'user not found' });
    res.json({ success: true, user: r.rows[0] });
  } catch (err) {
    console.error('auth error', err);
    return res.status(401).json({ success: false, message: 'invalid token' });
  }
});

// Start server after ensuring schema
ensureSchema()
  .then(() => {
    app.listen(PORT, () => console.log(`Backend started on ${PORT}`));
  })
  .catch(err => {
    console.error('Failed to ensure schema', err);
    process.exit(1);
  });
```

### Dockerfile (backend)
`three-tier/backend/Dockerfile`:
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --only=production || npm install --only=production
COPY . .
EXPOSE 8080
CMD ["node", "app.js"]
```

---

# 3. Kubernetes manifests (k8s/)
Create folder `three-tier/k8s` and add the following YAML files.

### postgres-pvc.yaml
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: three-tier
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 8Gi
  storageClassName: gp2
```

### postgres-deployment.yaml
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: three-tier
spec:
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:13
        env:
        - name: POSTGRES_DB
          value: "myapp"
        - name: POSTGRES_USER
          value: "postgres"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: pg-secret
              key: POSTGRES_PASSWORD
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: pgdata
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: pgdata
        persistentVolumeClaim:
          claimName: postgres-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: three-tier
spec:
  selector:
    app: postgres
  ports:
    - port: 5432
      targetPort: 5432
  type: ClusterIP
```

### backend-deployment.yaml
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: three-tier
spec:
  replicas: 2
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: backend
        image: YOUR_DOCKERHUB_USER/three-tier-backend:1.0
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 8080
        env:
        - name: PORT
          value: "8080"
        - name: DB_HOST
          value: "postgres"
        - name: DB_PORT
          value: "5432"
        - name: DB_USER
          value: "postgres"
        - name: DB_NAME
          value: "myapp"
        - name: DB_PASS
          valueFrom:
            secretKeyRef:
              name: pg-secret
              key: POSTGRES_PASSWORD
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: pg-secret
              key: JWT_SECRET
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: backend
  namespace: three-tier
spec:
  selector:
    app: backend
  ports:
    - port: 8080
      targetPort: 8080
  type: ClusterIP
```

### frontend-deployment.yaml
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: three-tier
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
      - name: frontend
        image: YOUR_DOCKERHUB_USER/frontend:1.0
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: frontend
  namespace: three-tier
spec:
  selector:
    app: frontend
  ports:
    - port: 80
      targetPort: 80
  type: ClusterIP
```

### app-ingress.yaml
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: three-tier-ingress
  namespace: three-tier
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-staging"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
spec:
  tls:
  - hosts:
    - ganga888.online
    secretName: ganga888-tls
  rules:
  - host: ganga888.online
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: backend
            port:
              number: 8080
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
```

### cluster-issuer-staging.yaml
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: you@yourdomain.com
    privateKeySecretRef:
      name: letsencrypt-staging-account-key
    solvers:
      - http01:
          ingress:
            class: nginx
```

---

# 4. Step-by-step commands (one sequence)

> Replace placeholders:
> - `YOUR_DOCKERHUB_USER` → your DockerHub username or ECR repo
> - `POSTGRES_PASSWORD` and `JWT_SECRET` → strong secrets (do NOT commit)
> - update cluster-issuer email to your address

```bash
# 0. prerequisites: have kubectl context pointing to your kops cluster
kubectl config current-context

# 1. create namespace
kubectl create namespace three-tier

# 2. create secrets (replace values)
kubectl -n three-tier create secret generic pg-secret \
  --from-literal=POSTGRES_PASSWORD='ChangeMePG!' \
  --from-literal=JWT_SECRET='ChangeMeJWTVerySecret!'

# 3. build & push backend image (from project root)
# cd three-tier/backend
docker build -t YOUR_DOCKERHUB_USER/three-tier-backend:1.0 ./backend
docker push YOUR_DOCKERHUB_USER/three-tier-backend:1.0

# 4. build & push frontend image (from project root)
# cd three-tier/frontend
docker build -t YOUR_DOCKERHUB_USER/frontend:1.0 ./frontend
docker push YOUR_DOCKERHUB_USER/frontend:1.0

# 5. apply PVC
kubectl apply -f k8s/postgres-pvc.yaml
kubectl -n three-tier get pvc postgres-pvc -w

# 6. deploy Postgres
kubectl apply -f k8s/postgres-deployment.yaml
kubectl -n three-tier rollout status deployment/postgres

# 7. deploy backend
# edit k8s/backend-deployment.yaml to set image to YOUR_DOCKERHUB_USER/three-tier-backend:1.0
kubectl apply -f k8s/backend-deployment.yaml
kubectl -n three-tier rollout status deployment/backend

# 8. deploy frontend
# edit k8s/frontend-deployment.yaml to set image to YOUR_DOCKERHUB_USER/frontend:1.0
kubectl apply -f k8s/frontend-deployment.yaml
kubectl -n three-tier rollout status deployment/frontend

# 9. (optional) install cert-manager for TLS
kubectl apply --validate=false -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
kubectl apply -f k8s/cluster-issuer-staging.yaml

# 10. install nginx ingress controller (if not present)
# using ingress-nginx Helm or manifests – simplest quick manifest (replace with helm in prod)
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.9.0/deploy/static/provider/cloud/deploy.yaml

# 11. apply Ingress
# ensure k8s/app-ingress.yaml uses cert-manager.io/cluster-issuer: letsencrypt-staging
kubectl apply -f k8s/app-ingress.yaml
kubectl -n three-tier get ingress three-tier-ingress -w

# 12. DNS: point ganga888.online to the ingress external IP
# find ingress external IP (ingress-nginx namespace service)
kubectl -n ingress-nginx get svc ingress-nginx-controller
# add A record in your DNS provider pointing ganga888.online -> EXTERNAL-IP

# 13. verify
# open https://ganga888.online in browser
# test signup/login via UI

# 14. debug commands
kubectl -n three-tier get pods
kubectl -n three-tier logs deployment/backend
kubectl -n three-tier port-forward svc/backend 8080:8080 &
curl http://localhost:8080/health
```

---

# 5. What to expect

- Browse to `https://ganga888.online/` → frontend loads. Sign up and login work via `/api` routes. After login frontend stores JWT in localStorage.
- Postgres stores users on an EBS-backed PVC so restarting pods keeps data.
- Ingress + cert-manager handles TLS. Use staging issuer first, then switch to production issuer to get real certs.

---

# 6. Production suggestions

- Use AWS RDS for Postgres in production.
- Add resource limits, HPA, RBAC, NetworkPolicies.
- Use private image registry or ECR with node IAM role.
- Rotate JWT secret carefully (requires session invalidation strategy).
- Replace staging cert-manager issuer with production after testing.

---

# 7. Quick troubleshooting

- `kubectl -n three-tier get events` – check for PVC provisioning failures.
- If pods CrashLoopBackOff: `kubectl -n three-tier logs <pod>` and `kubectl describe pod <pod>`.
- If cert-manager fails, check Orders and Challenges in `kubectl -n cert-manager get orders,challenges`.

---

If you want I can now:
- (A) produce downloadable `tar.gz` with all files, or
- (B) convert k8s yamls to a Helm chart or Kustomize overlay,
- (C) change Postgres Deployment to a StatefulSet and stable volumeClaimTemplates.

Tell me which one you want next and I'll add it to this document.

