import sys
import os

# Append 'backend' directory to sys.path so app modules can be imported
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.main import app

# Vercel serverless function entrypoint
