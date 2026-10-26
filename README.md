# OSINT-to-Attack-Path

Automated Passive Reconnaissance & Attack Path Prioritization Framework for authorized security testing, posture analysis, and academic research.

---

## 📁 Project Structure

```text
OSINT-to-Attack-Path/
├── backend/                  # FastAPI backend application
│   ├── app/
│   │   ├── collectors/       # OSINT modules (DNS, Domain, IP, Certs, Threat Intel, etc.)
│   │   ├── demo/             # Preloaded realistic simulation datasets
│   │   ├── models/           # Database models (Findings, Relationships, Attack Paths)
│   │   ├── routers/          # API endpoint routes
│   │   ├── schemas/          # Pydantic data schemas
│   │   ├── services/         # Correlation engine, defense scoring, risk calculations
│   │   ├── config.py         # Application settings and environment loader
│   │   ├── database.py       # Async SQLite database setup
│   │   ├── main.py           # FastAPI entry point
│   │   └── utils.py          # Shared utility helpers
│   ├── tests/                # Unit test suites
│   ├── .env                  # Backend environment variables
│   └── requirements.txt      # Python dependencies
├── docs/                     # Technical documentation and architecture reports
│   └── technical_report.md
├── frontend/                 # Vite + React single-page application
│   ├── public/               # Static assets & SVG icons
│   ├── src/
│   │   ├── components/       # Layout and reusable UI components
│   │   ├── pages/            # View pages (Dashboard, Recon, Attack Paths, Defense, etc.)
│   │   ├── services/         # API client bindings
│   │   ├── stores/           # Zustand state store
│   │   ├── utils/            # Formatting & rendering helpers
│   │   ├── App.jsx           # Main application router
│   │   ├── index.css         # Design system & styles
│   │   └── main.jsx          # React DOM mount point
│   ├── package.json          # Frontend npm scripts & dependencies
│   └── vite.config.js        # Vite configuration & backend proxy
├── .env.example              # Environment variables template
├── package.json              # Root workspace convenience scripts
└── render.yaml               # Deployment blueprint
```

---

## 🚀 Getting Started

### 1. Environment Configuration

Copy `.env.example` to `backend/.env` (and optionally to root):
```bash
cp .env.example backend/.env
```

Default settings operate in **Demo Mode** (`OSINT_MODE=demo`), requiring no external API keys.

---

### 2. Backend Setup & Run

```bash
# Navigate to backend directory
cd backend

# Install Python requirements
pip install -r requirements.txt

# Run backend development server
python -m uvicorn app.main:app --reload --port 8000
```

- **API Root**: `http://localhost:8000`
- **Interactive API Docs (Swagger)**: `http://localhost:8000/docs`

#### Run Tests
```bash
cd backend
python -m unittest discover -s tests
```

---

### 3. Frontend Setup & Run

```bash
# Navigate to frontend directory
cd frontend

# Install Node dependencies
npm install

# Start Vite dev server
npm run dev
```

- **Frontend Application**: `http://localhost:5173`

---

## 🛠️ Root Convenience Scripts

You can also control the frontend directly from the project root:
```bash
npm run dev:frontend      # Start Vite dev server
npm run build:frontend    # Compile production bundle
```
