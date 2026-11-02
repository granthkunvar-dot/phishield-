#!/usr/bin/env bash
# ==============================================================================
# Phishield Automated Setup Script for macOS (Apple Silicon M1/M2/M3/M4/M5) & Linux
# ==============================================================================

set -e

echo "=================================================================="
echo "  Setting up Phishield on macOS / Linux"
echo "=================================================================="

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed or not in PATH."
    echo "Please install Python 3 (e.g., via Homebrew: brew install python) and try again."
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "Found: $PYTHON_VERSION"

# Create virtual environment if not present
if [ ! -d "venv" ]; then
    echo "Creating virtual environment in ./venv..."
    python3 -m venv venv
else
    echo "Virtual environment ./venv already exists."
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing project dependencies from requirements.txt..."
pip install -r requirements.txt

# Verify ML model existence; train if missing
if [ ! -f "ml/models/phishield_rf_model.joblib" ]; then
    echo "ML model not found. Generating dataset and training Random Forest model..."
    python ml/dataset_generator.py
    python ml/train_models.py
    python ml/drift_eval.py
else
    echo "Verified: Pre-trained Random Forest model exists at ml/models/phishield_rf_model.joblib"
fi

# Run pytest suite
echo "Running test suite to verify installation integrity..."
pytest --cov=app --cov-report=term-missing tests/

echo "=================================================================="
echo "  Phishield setup completed successfully!"
echo "  To launch the web application:"
echo "    ./run.sh"
echo "  Or manually:"
echo "    source venv/bin/activate"
echo "    python run.py"
echo "=================================================================="

