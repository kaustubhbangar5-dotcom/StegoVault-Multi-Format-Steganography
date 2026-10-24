"""
StegoVault - Vercel Serverless Function Handler
Initializes and exposes the Flask WSGI application for Vercel Python runtime.
"""
import sys
import os

# Append project root directory to sys.path so modules resolve correctly
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app

# Vercel entrypoint looks for 'app' or 'handler'
handler = app
