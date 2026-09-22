#!/usr/bin/env python3
# HackGPT core module
"""
HackGPT Test Suite
Run this script to validate your HackGPT installation
"""

import os
import sys
import subprocess
import importlib
import shutil
from pathlib import Path

# Ensure Unicode output works on Windows consoles (cp1252, etc.)
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def test_python_dependencies():
    """Test if all Python dependencies are installed"""
    print("🐍 Testing Python dependencies...")
    
    required_packages = [
        'requests', 'openai', 'rich', 'speech_recognition',
        'pyttsx3', 'flask'
    ]
    
    missing = []
    for package in required_packages:
        try:
            importlib.import_module(package)
            print(f"  ✅ {package}")
        except ImportError:
            missing.append(package)
            print(f"  ❌ {package}")
    
    return len(missing) == 0, missing

def test_system_tools():
    """Test if required system tools are installed"""
    print("\n🔧 Testing system tools...")
    
    required_tools = [
        'nmap', 'masscan', 'nikto', 'gobuster', 'sqlmap',
        'hydra', 'theharvester', 'enum4linux', 'whatweb'
    ]
    
    missing = []
    for tool in required_tools:
        if shutil.which(tool):
            print(f"  ✅ {tool}")
        else:
            missing.append(tool)
            print(f"  ❌ {tool}")
    
    return len(missing) == 0, missing

def test_ollama():
    """Test if ollama is installed and model is available"""
    print("\n🤖 Testing local AI (Ollama)...")
    
    # Check if ollama is installed
    if not shutil.which('ollama'):
        print("  ❌ Ollama not installed")
        return False, ["ollama"]
    
    print("  ✅ Ollama installed")
    
    # Check if model is available
    result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
    if 'llama2:7b' in result.stdout:
        print("  ✅ Llama2 model available")
        return True, []
    else:
        print("  ❌ Llama2 model not found")
        return False, ["llama2:7b model"]

def test_permissions():
    """Test if required directories and permissions are set"""
    print("\n📁 Testing permissions...")
    
    # Test reports directory — prefer local ./reports on all platforms
    reports_dir = Path('./reports')
    if sys.platform != "win32" and Path('/reports').exists():
        reports_dir = Path('/reports')
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
    except (OSError, PermissionError):
        pass
    if reports_dir.exists() and os.access(reports_dir, os.W_OK):
        print(f"  ✅ {reports_dir} directory writable")
        reports_ok = True
    else:
        print(f"  ❌ {reports_dir} directory not writable")
        reports_ok = False
    
    # Test advance_hackgpt.py exists and is readable
    hackgpt_path = Path('./advance_hackgpt.py')
    if hackgpt_path.exists() and os.access(hackgpt_path, os.R_OK):
        # On Windows, .py files are not marked executable; existence + readable is sufficient
        print("  ✅ advance_hackgpt.py is accessible")
        script_ok = True
    else:
        print("  ❌ advance_hackgpt.py not found or not readable")
        script_ok = False
    
    return reports_ok and script_ok, []

def test_openai_api():
    """Test OpenAI API key if provided"""
    print("\n🌐 Testing OpenAI API...")
    
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("  ℹ️  No OpenAI API key found (will use local AI)")
        return True, []
    
    try:
        import openai
        client = openai.OpenAI(api_key=api_key)
        
        # Test API with a simple request
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "Test"}],
            max_tokens=5
        )
        print("  ✅ OpenAI API working")
        return True, []
    except Exception as e:
        print(f"  ❌ OpenAI API error: {e}")
        return False, [str(e)]

def run_basic_functionality_test():
    """Run a basic functionality test"""
    print("\n🚀 Testing basic functionality...")
    
    try:
        # Import the main HackGPT class
        sys.path.insert(0, '.')
        from advance_hackgpt import HackGPT, AIEngine, ToolManager
        
        print("  ✅ HackGPT imports successful")
        
        # Test AI Engine initialization
        ai = AIEngine()
        print("  ✅ AI Engine initialized")
        
        # Test Tool Manager
        tools = ToolManager()
        print("  ✅ Tool Manager initialized")
        
        # Test HackGPT main class
        hackgpt = HackGPT()
        print("  ✅ HackGPT main class initialized")
        
        return True, []
        
    except Exception as e:
        print(f"  ❌ Functionality test failed: {e}")
        return False, [str(e)]

def main():
    """Run all tests"""
    print("🔥 HackGPT Installation Test Suite 🔥")
    print("=" * 40)
    
    all_passed = True
    all_issues = []
    
    # Run all tests
    tests = [
        ("Python Dependencies", test_python_dependencies),
        ("System Tools", test_system_tools),
        ("Local AI (Ollama)", test_ollama),
        ("Permissions", test_permissions),
        ("OpenAI API", test_openai_api),
        ("Basic Functionality", run_basic_functionality_test)
    ]
    
    for test_name, test_func in tests:
        passed, issues = test_func()
        if not passed:
            all_passed = False
            all_issues.extend(issues)
    
    # Summary
    print("\n" + "=" * 40)
    if all_passed:
        print("🎉 All tests passed! HackGPT is ready to use.")
        print("\nQuick start:")
        print("  ./advance_hackgpt.py            # Interactive mode")
        print("  ./advance_hackgpt.py --web      # Web dashboard")
        print("  ./advance_hackgpt.py --voice    # Voice commands")
    else:
        print("❌ Some tests failed. Issues found:")
        for issue in all_issues:
            print(f"  - {issue}")
        print("\nRun './install.sh' to fix missing dependencies.")
    
    print("\n" + "=" * 40)
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
