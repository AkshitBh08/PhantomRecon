import os
import sys
import subprocess

def install_python_dependencies():
    """Installs required Python dependencies."""
    try:
        print("Installing required Python dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "shodan", "python-nmap", "python-whois", "colorama"])
        print("Python dependencies installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Error installing Python dependencies: {e}")
        sys.exit(1)

def check_nmap_installation():
    """Checks if Nmap is installed on the system and prompts for installation if missing."""
    try:
        print("Checking if Nmap is installed...")
        subprocess.check_call(["nmap", "-v"])
        print("Nmap is already installed.")
    except subprocess.CalledProcessError:
        print("Nmap is not installed. You can install it from https://nmap.org/download.html.")
        sys.exit(1)

def main():
    install_python_dependencies()
    check_nmap_installation()
    print("Installation completed successfully.")

if __name__ == "__main__":
    main()
