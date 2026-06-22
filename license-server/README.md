# 🔑 Licensify — License Management System

A self-contained license key management system with admin dashboard and validation API. Built with Node.js, Express, and SQLite.

## Features

- **License Generation** — Create unique license keys in `XXXX-XXXX-XXXX-XXXX` format
- **Flexible Duration** — Set expiry in minutes, hours, days, or make permanent
- **Validation API** — Public endpoint to validate license keys with API key auth
- **Admin Dashboard** — Full-featured web UI to manage all licenses
- **Statistics** — Real-time dashboard with license status breakdown
- **Search & Filter** — Find licenses by key, user, or status
- **CSV Export** — Export all licenses to CSV
- **Dark Mode** — Toggle between light and dark themes
- **Rate Limiting** — Built-in protection against abuse
- **SQLite Database** — Zero configuration, auto-creates on first run

## Quick Start

### 1. Install Dependencies

```bash
cd license-server
npm install
```

### 2. Start the Server

```bash
npm start
```

Or for development (with auto-restart on file changes):

```bash
npm run dev
```

### 3. Access the Dashboard

Open your browser and navigate to:

```
http://localhost:3000
```

**Default login credentials:**
- Username: `admin`
- Password: `admin123`

## Deployment on a VPS

### Prerequisites

- A Linux VPS (Ubuntu 20.04+ recommended)
- Node.js 18+ installed
- A domain name (optional, for production)

### Step 1: Install Node.js

```bash
# Install Node.js 18+ using NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify installation
node --version
npm --version
```

### Step 2: Upload the Application

```bash
# Create app directory
mkdir -p /opt/licensify
cd /opt/licensify

# Upload files using SCP (from your local machine)
scp -r license-server/* user@your-vps-ip:/opt/licensify/

# Or clone from a git repository
```

### Step 3: Install Dependencies & Start

```bash
cd /opt/licensify
npm install --production
```

### Step 4: Configure Environment (Optional)

```bash
# Create a .env file for custom configuration
cat > /opt/licensify/.env << 'EOF'
PORT=3000
JWT_SECRET=your-very-secret-key-here
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-strong-password-here
API_KEY=your-custom-api-key-here
EOF
```

The app works without any environment variables — secure defaults are auto-generated.

### Step 5: Run with PM2 (Production Process Manager)

```bash
# Install PM2 globally
sudo npm install -g pm2

# Start the application
cd /opt/licensify
pm2 start server.js --name licensify

# Save PM2 process list
pm2 save

# Set PM2 to start on system boot
pm2 startup
```

### Step 6: Set Up Nginx Reverse Proxy (Optional)

```bash
sudo apt-get install -y nginx
```

Create an Nginx config:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
# Enable the site
sudo ln -s /etc/nginx/sites-available/licensify /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Set up SSL with Certbot
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

## API Reference

### Authentication

All admin endpoints require a Bearer token in the `Authorization` header.

```
Authorization: Bearer <your-jwt-token>
```

### Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/login` | No | Admin login |
| POST | `/api/auth/logout` | Yes | Admin logout |
| GET | `/api/auth/me` | Yes | Get current user |
| GET | `/api/licenses` | Yes | List all licenses |
| POST | `/api/licenses` | Yes | Generate new license |
| GET | `/api/licenses/:id` | Yes | Get license details |
| PUT | `/api/licenses/:id` | Yes | Update license |
| DELETE | `/api/licenses/:id` | Yes | Delete license |
| GET | `/api/stats` | Yes | Dashboard statistics |
| GET | `/api/licenses/export/csv` | Yes | Export licenses as CSV |
| POST | `/api/validate` | API Key | Validate a license key |

### Validate a License Key (Public API)

```bash
curl -X POST http://localhost:3000/api/validate \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-api-key" \
  -d '{"license_key": "ABCD-1234-EFGH-5678"}'
```

**Responses:**

✅ Valid license:
```json
{
  "valid": true,
  "license_key": "ABCD-1234-EFGH-5678",
  "is_permanent": false,
  "expires_at": "2025-01-15T00:00:00.000Z",
  "created_at": "2025-01-01T00:00:00.000Z",
  "validations_remaining": 14
}
```

❌ Invalid license:
```json
{
  "valid": false,
  "error": "License has expired.",
  "license_key": "ABCD-1234-EFGH-5678",
  "expires_at": "2024-01-01T00:00:00.000Z"
}
```

### Generate a License

```bash
curl -X POST http://localhost:3000/api/licenses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-jwt-token" \
  -d '{
    "duration_days": 30,
    "duration_hours": 0,
    "duration_minutes": 0,
    "is_permanent": false,
    "user_name": "John Doe",
    "user_email": "john@example.com",
    "notes": "Premium license"
  }'
```

## Security Notes

1. **Change the default password** immediately after first login.
2. The JWT secret and API key are auto-generated on first run and saved in memory.
3. Rate limiting is enabled on all endpoints to prevent abuse.
4. SQLite database file (`licenses.db`) is created in the app directory.
5. For production, always run behind a reverse proxy with SSL.

## File Structure

```
license-server/
├── server.js           # Main application (all routes & logic)
├── package.json        # Dependencies
├── licenses.db         # SQLite database (auto-created)
├── .api_key            # Auto-generated API key
├── public/
│   └── index.html      # Admin dashboard (single-file app)
└── README.md           # This file
```

## License

MIT