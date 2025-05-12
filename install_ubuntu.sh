#!/bin/bash
echo "Installing PDF Scanner requirements offline (Ubuntu)..."

# Change to the script's directory
cd "$(dirname "$0")"

# Install local .deb dependencies
echo "Installing .deb packages..."
sudo dpkg -i ubuntu_debs/*.deb

# Install Python packages from local .whl files
echo "Installing Python packages from local files..."
pip install --no-index --find-links=packages -r requirements.txt

echo "✅ Installation complete. You can now run the scanner with:"
echo "python3 part2.py"
