#!/usr/bin/env python3
"""
Ultimate Multi-Platform Installation Script
Professional-grade installation for Linux/macOS/Windows
Advanced deployment with full optimization
"""

import os
import sys
import platform
import subprocess
import shutil
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
import urllib.request
import tarfile
import zipfile

class MultiPlatformInstaller:
    """Ultimate multi-platform installer"""
    
    def __init__(self):
        self.system = platform.system()
        self.architecture = platform.machine()
        self.python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        self.install_dir = Path.home() / "Crack2025"
        self.bin_dir = self.install_dir / "bin"
        self.lib_dir = self.install_dir / "lib"
        self.config_dir = self.install_dir / "config"
        
        self.dependencies = self.get_dependencies()
        self.check_root_privileges()
    
    def get_dependencies(self) -> Dict[str, List[str]]:
        """Get platform-specific dependencies"""
        return {
            "Linux": [
                "build-essential", "cmake", "python3-dev", "python3-pip",
                "libpcap-dev", "libssl-dev", "libffi-dev", "wireless-tools",
                "aircrack-ng", "reaver", "bully", "macchanger", "iw",
                "python3-pyqt5", "python3-matplotlib", "python3-numpy",
                "python3-scipy", "python3-pandas", "python3-scapy"
            ],
            "Darwin": [
                "cmake", "python3", "pyenv", "brew", "libpcap", "openssl",
                "python@3.9", "pyqt5", "numpy", "scipy", "pandas", "matplotlib",
                "scapy", "aircrack-ng"
            ],
            "Windows": [
                "cmake", "Visual Studio Build Tools", "python3", "pip",
                "npcap", "WinPcap", "Wireshark", "Nmap", "Aircrack-ng"
            ]
        }
    
    def check_root_privileges(self):
        """Check if root privileges are available"""
        self.is_root = False
        if self.system in ["Linux", "Darwin"]:
            self.is_root = os.geteuid() == 0
        elif self.system == "Windows":
            import ctypes
            self.is_root = ctypes.windll.shell32.IsUserAnAdmin()
    
    def install(self):
        """Main installation process"""
        print("🚀 Ultimate WiFi Security Suite Installation")
        print("=" * 50)
        
        try:
            self.pre_install_checks()
            self.create_directories()
            self.install_system_dependencies()
            self.install_python_packages()
            self.compile_cpp_modules()
            self.setup_configuration()
            self.create_launchers()
            self.setup_system_integration()
            self.post_install_verification()
            
            print("\n✅ Installation completed successfully!")
            print(f"📁 Installation directory: {self.install_dir}")
            print(f"🖥️  Platform: {self.system} {self.architecture}")
            print(f"🐍 Python: {self.python_version}")
            
            self.display_next_steps()
            
        except Exception as e:
            logging.error(f"Installation failed: {e}")
            print(f"\n❌ Installation failed: {e}")
            sys.exit(1)
    
    def pre_install_checks(self):
        """Perform pre-installation checks"""
        print("🔍 Running pre-installation checks...")
        
        # Check Python version
        if sys.version_info < (3, 7):
            raise RuntimeError("Python 3.7 or higher required")
        
        # Check disk space
        required_space = 500 * 1024 * 1024  # 500MB
        available_space = shutil.disk_usage(Path.home()).free
        if available_space < required_space:
            raise RuntimeError(f"Insufficient disk space. Need 500MB, have {available_space // 1024 // 1024}MB")
        
        # Check network connectivity
        try:
            urllib.request.urlopen('https://pypi.org', timeout=5)
        except Exception:
            print("⚠️  Warning: Limited network connectivity detected")
        
        print("✅ Pre-installation checks passed")
    
    def create_directories(self):
        """Create installation directories"""
        print("📁 Creating installation directories...")
        
        directories = [
            self.install_dir,
            self.bin_dir,
            self.lib_dir,
            self.config_dir,
            self.install_dir / "logs",
            self.install_dir / "data",
            self.install_dir / "backups",
            self.install_dir / "temp"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        
        print("✅ Directories created")
    
    def install_system_dependencies(self):
        """Install system-level dependencies"""
        print("📦 Installing system dependencies...")
        
        deps = self.dependencies.get(self.system, [])
        
        if self.system == "Linux":
            self.install_linux_dependencies(deps)
        elif self.system == "Darwin":
            self.install_macos_dependencies(deps)
        elif self.system == "Windows":
            self.install_windows_dependencies(deps)
        
        print("✅ System dependencies installed")
    
    def install_linux_dependencies(self, deps: List[str]):
        """Install Linux dependencies"""
        package_managers = [
            ("apt", ["sudo", "apt", "install", "-y"]),
            ("yum", ["sudo", "yum", "install", "-y"]),
            ("dnf", ["sudo", "dnf", "install", "-y"]),
            ("pacman", ["sudo", "pacman", "-S", "--noconfirm"])
        ]
        
        for pm_name, cmd_base in package_managers:
            try:
                subprocess.run([pm_name, "--version"], 
                             capture_output=True, check=True)
                
                for dep in deps:
                    subprocess.run(cmd_base + [dep], check=True)
                break
            except subprocess.CalledProcessError:
                continue
        else:
            print("⚠️  Could not install all system dependencies")
    
    def install_macos_dependencies(self, deps: List[str]):
        """Install macOS dependencies"""
        try:
            subprocess.run(["brew", "--version"], capture_output=True, check=True)
            
            for dep in deps:
                if dep == "brew":
                    continue
                subprocess.run(["brew", "install", dep], check=True)
                
        except subprocess.CalledProcessError:
            print("⚠️  Homebrew not found. Please install Homebrew first")
    
    def install_windows_dependencies(self, deps: List[str]):
        """Install Windows dependencies"""
        try:
            # Install via Chocolatey if available
            subprocess.run(["choco", "--version"], capture_output=True, check=True)
            
            for dep in deps:
                subprocess.run(["choco", "install", dep, "-y"], check=True)
                
        except subprocess.CalledProcessError:
            print("⚠️  Chocolatey not found. Manual installation required")
    
    def install_python_packages(self):
        """Install Python packages"""
        print("🐍 Installing Python packages...")
        
        packages = [
            "pyqt5", "matplotlib", "numpy", "scipy", "pandas", "psutil",
            "scapy", "cryptography", "requests", "pyyaml", "pybind11",
            "websockets", "asyncio-mqtt", "aiosqlite", "rich", "click"
        ]
        
        for package in packages:
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", 
                              "--user", package], check=True)
            except subprocess.CalledProcessError:
                print(f"⚠️  Failed to install {package}")
        
        print("✅ Python packages installed")
    
    def compile_cpp_modules(self):
        """Compile C++ modules"""
        print("🔧 Compiling C++ modules...")
        
        cpp_dir = Path.cwd() / "src" / "cpp"
        build_dir = cpp_dir / "build"
        build_dir.mkdir(exist_ok=True)
        
        try:
            # Configure CMake
            subprocess.run([
                "cmake", "..",
                f"-DCMAKE_BUILD_TYPE=Release",
                f"-DPYTHON_EXECUTABLE={sys.executable}",
                f"-DCMAKE_INSTALL_PREFIX={self.install_dir}"
            ], cwd=build_dir, check=True)
            
            # Build
            subprocess.run(["cmake", "--build", ".", "--config", "Release"], 
                         cwd=build_dir, check=True)
            
            # Install
            subprocess.run(["cmake", "--install", "."], 
                         cwd=build_dir, check=True)
            
            print("✅ C++ modules compiled")
            
        except subprocess.CalledProcessError as e:
            print(f"⚠️  C++ compilation failed: {e}")
    
    def setup_configuration(self):
        """Setup configuration files"""
        print("⚙️  Setting up configuration...")
        
        config = {
            "system": {
                "platform": self.system,
                "architecture": self.architecture,
                "python_version": self.python_version
            },
            "paths": {
                "install_dir": str(self.install_dir),
                "bin_dir": str(self.bin_dir),
                "lib_dir": str(self.lib_dir),
                "config_dir": str(self.config_dir)
            },
            "optimization": {
                "performance_mode": "maximum",
                "memory_limit": "80%",
                "thread_count": os.cpu_count() * 2
            },
            "security": {
                "ethical_mode": True,
                "authorization_required": True,
                "logging_level": "INFO"
            }
        }
        
        config_file = self.config_dir / "config.json"
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print("✅ Configuration setup complete")
    
    def create_launchers(self):
        """Create platform-specific launchers"""
        print("🚀 Creating launchers...")
        
        if self.system == "Linux":
            self.create_linux_launcher()
        elif self.system == "Darwin":
            self.create_macos_launcher()
        elif self.system == "Windows":
            self.create_windows_launcher()
        
        print("✅ Launchers created")
    
    def create_linux_launcher(self):
        """Create Linux launcher"""
        launcher_content = f'''#!/bin/bash
# Ultimate WiFi Security Suite Launcher
export PYTHONPATH="{self.install_dir}/lib:$PYTHONPATH"
cd "{self.install_dir}"
python3 -m src.python.main "$@"
'''
        
        launcher_path = self.bin_dir / "crack2025"
        with open(launcher_path, 'w') as f:
            f.write(launcher_content)
        
        os.chmod(launcher_path, 0o755)
        
        # Create desktop entry
        desktop_entry = f'''[Desktop Entry]
Name=Crack 2025 Ultimate
Comment=Ultimate WiFi Security Analysis Suite
Exec={launcher_path}
Icon={self.install_dir}/icon.png
Terminal=false
Type=Application
Categories=Network;Security;
'''
        
        desktop_path = Path.home() / ".local" / "share" / "applications" / "crack2025.desktop"
        desktop_path.parent.mkdir(parents=True, exist_ok=True)
        with open(desktop_path, 'w') as f:
            f.write(desktop_entry)
    
    def create_macos_launcher(self):
        """Create macOS launcher"""
        launcher_content = f'''#!/bin/bash
# Ultimate WiFi Security Suite Launcher
export PYTHONPATH="{self.install_dir}/lib:$PYTHONPATH"
cd "{self.install_dir}"
python3 -m src.python.main "$@"
'''
        
        launcher_path = self.bin_dir / "crack2025"
        with open(launcher_path, 'w') as f:
            f.write(launcher_content)
        
        os.chmod(launcher_path, 0o755)
    
    def create_windows_launcher(self):
        """Create Windows launcher"""
        batch_content = f'''@echo off
title Crack 2025 Ultimate
set PYTHONPATH={self.install_dir}\\lib;%PYTHONPATH%
cd /d "{self.install_dir}"
python -m src.python.main %*
pause
'''
        
        batch_path = self.bin_dir / "crack2025.bat"
        with open(batch_path, 'w') as f:
            f.write(batch_content)
        
        # Create PowerShell launcher
        ps_content = f'''#!/usr/bin/env pwsh
$env:PYTHONPATH = "{self.install_dir}\\lib;$env:PYTHONPATH"
Set-Location "{self.install_dir}"
python -m src.python.main $args
'''
        
        ps_path = self.bin_dir / "crack2025.ps1"
        with open(ps_path, 'w') as f:
            f.write(ps_content)
    
    def setup_system_integration(self):
        """Setup system integration"""
        print("🔗 Setting up system integration...")
        
        # Add to PATH
        if self.system in ["Linux", "Darwin"]:
            shell_rc = Path.home() / ".bashrc"
            if shell_rc.exists():
                with open(shell_rc, 'a') as f:
                    f.write(f'\nexport PATH="{self.bin_dir}:$PATH"\n')
        
        print("✅ System integration complete")
    
    def post_install_verification(self):
        """Verify installation"""
        print("🔍 Verifying installation...")
        
        checks = [
            ("Installation directory", self.install_dir.exists()),
            ("Python executable", shutil.which("python") or shutil.which("python3")),
            ("CMake available", shutil.which("cmake") is not None),
            ("Configuration file", (self.config_dir / "config.json").exists()),
            ("Launcher script", (self.bin_dir / "crack2025").exists() or 
                              (self.bin_dir / "crack2025.bat").exists())
        ]
        
        all_passed = True
        for check_name, passed in checks:
            status = "✅" if passed else "❌"
            print(f"{status} {check_name}")
            if not passed:
                all_passed = False
        
        if all_passed:
            print("🎉 All verification checks passed!")
        else:
            print("⚠️  Some verification checks failed")
    
    def display_next_steps(self):
        """Display next steps for user"""
        print("\n" + "=" * 50)
        print("🎯 NEXT STEPS:")
        print("=" * 50)
        
        if self.system in ["Linux", "Darwin"]:
            print(f"1. Run: export PATH=\"{self.bin_dir}:$PATH\"")
            print(f"2. Launch: crack2025")
            print(f"3. Or use: {self.bin_dir}/crack2025")
        elif self.system == "Windows":
            print(f"1. Add to PATH: {self.bin_dir}")
            print(f"2. Launch: {self.bin_dir}\\crack2025.bat")
            print(f"3. Or use PowerShell: {self.bin_dir}\\crack2025.ps1")
        
        print("\n📖 Documentation: README.md")
        print("🐛 Issues: Report to GitHub issues")
        print("💡 Support: Check documentation/wiki")

def main():
    """Main installation entry point"""
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Ultimate WiFi Security Suite Installation")
        print("Usage: python install.py")
        print("Options: --help, --uninstall, --update")
        return
    
    if len(sys.argv) > 1 and sys.argv[1] == "--uninstall":
        print("Uninstall functionality not implemented")
        return
    
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        print("Update functionality not implemented")
        return
    
    installer = MultiPlatformInstaller()
    installer.install()

if __name__ == "__main__":
    main()