#!/bin/bash
set -e
cd "$(dirname "$0")"

# Create venv if not exists
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

# Install/update dependencies
pip install -q -r requirements.txt
pip install -q python-dotenv

echo ""
echo "=========================================="
echo "  Pentest AI Platform"
echo "  URL: http://localhost:5000"
echo "  Admin: admin / Admin@123456"
echo "=========================================="
echo ""

python run.py
