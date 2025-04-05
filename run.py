#!/usr/bin/env python3
"""
Main entry point for the Password Security Demo.
Allows choosing between the CLI and Web interface.
"""

import subprocess
import sys
import os
import webbrowser
from threading import Timer

def run_web_app():
    """Starts the Flask web server."""
    try:
        # Import Flask app instance here to avoid circular imports if run.py imports web_app
        from web_app import app 
        
        port = 5000 # Default Flask port
        url = f"http://127.0.0.1:{port}"
        
        # Open the web browser shortly after starting the server
        Timer(1, lambda: webbrowser.open(url)).start()
        print(f"Starting web server on {url}")
        print("Open your browser to this address if it doesn't open automatically.")
        print("Press CTRL+C to stop the server.")
        
        # Run Flask development server (suitable for local use)
        # Use host='0.0.0.0' to make it accessible on your network if needed
        # debug=True provides auto-reloading and debugging info
        app.run(host='127.0.0.1', port=port, debug=False) 
        
    except ImportError:
        print("Error: Flask is not installed or web_app.py is missing.")
        print("Please install requirements: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"Failed to start web server: {e}")
        sys.exit(1)

def run_cli_app():
    """Runs the command-line interface."""
    try:
        # Use subprocess to run the CLI script in its own process
        # This avoids potential conflicts with Flask if run in the same process
        script_path = os.path.join(os.path.dirname(__file__), 'cli_app.py')
        if not os.path.exists(script_path):
             print(f"Error: Cannot find cli_app.py at {script_path}")
             sys.exit(1)
             
        # Ensure Python executable is found correctly
        python_executable = sys.executable
        if not python_executable:
            python_executable = "python3" # Fallback
            
        process = subprocess.run([python_executable, script_path], check=False)
        # Exit with the same code as the CLI script
        sys.exit(process.returncode)
        
    except FileNotFoundError:
         print(f"Error: Cannot find python executable '{python_executable}'. Make sure Python is in your PATH.")
         sys.exit(1)
    except Exception as e:
        print(f"Failed to run CLI app: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("Password Security Demonstration")
    print("Choose an interface:")
    print("  1. Command Line Interface (CLI)")
    print("  2. Web Interface (Local Web Server)")

    while True:
        choice = input("Enter your choice (1 or 2): ").strip()
        if choice == '1':
            run_cli_app()
            break
        elif choice == '2':
            run_web_app()
            break
        else:
            print("Invalid choice. Please enter 1 or 2.") 