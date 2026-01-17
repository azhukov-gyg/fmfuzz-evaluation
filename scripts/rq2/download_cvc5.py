#!/usr/bin/env python3
"""
Download latest CVC5 binary from GitHub releases
Usage: python3 scripts/rq2/download_cvc5.py [output_dir]
"""

import argparse
import os
import sys
import subprocess
import tempfile
import shutil
import requests
from pathlib import Path

def install_unzip():
    """Install unzip if not available"""
    if shutil.which('unzip'):
        return
    
    print("📦 Installing unzip...")
    try:
        subprocess.run(['sudo', 'apt-get', 'update'], check=True, capture_output=True)
        subprocess.run(['sudo', 'apt-get', 'install', '-y', 'unzip'], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Cannot install unzip automatically. Please install unzip manually.")
        sys.exit(1)

def get_latest_release(github_token=None):
    """Get the latest release from GitHub API"""
    url = "https://api.github.com/repos/cvc5/cvc5/releases/latest"
    headers = {
        'User-Agent': 'FM-Fuzz/1.0'  # GitHub API requires User-Agent header
    }
    if github_token:
        headers['Authorization'] = f'token {github_token}'
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"❌ Failed to get latest release: {e}")
        if hasattr(e, 'response') and e.response is not None and e.response.status_code == 403:
            print("⚠️ 403 Forbidden - This might be a rate limit issue. Consider setting GITHUB_TOKEN environment variable.")
        sys.exit(1)

def find_linux_binary(assets):
    """Find the Linux x86_64 static binary from assets"""
    for asset in assets:
        url = asset['browser_download_url']
        if all(kw in url.lower() for kw in ['linux', 'x86_64', 'static']):
            return url
    return None

def download_and_extract(asset_url, output_dir, github_token=None):
    """Download and extract the CVC5 binary"""
    print(f"📥 Downloading: {asset_url}")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "cvc5.zip")
        
        # Download
        headers = {
            'User-Agent': 'FM-Fuzz/1.0'  # GitHub API requires User-Agent header
        }
        if github_token:
            headers['Authorization'] = f'token {github_token}'
        try:
            response = requests.get(asset_url, headers=headers, timeout=60, stream=True)
            response.raise_for_status()
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        except requests.RequestException as e:
            print(f"❌ Failed to download: {e}")
            if hasattr(e, 'response') and e.response is not None and e.response.status_code == 403:
                print("⚠️ 403 Forbidden - This might be a rate limit issue. Consider setting GITHUB_TOKEN environment variable.")
            sys.exit(1)
        
        # Extract
        print("📦 Extracting...")
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        subprocess.run(['unzip', '-q', zip_path, '-d', extract_dir], check=True)
        
        # Find cvc5 binary
        for root, dirs, files in os.walk(extract_dir):
            if 'cvc5' in files:
                cvc5_bin = os.path.join(root, 'cvc5')
                if os.path.isfile(cvc5_bin):
                    output_path = os.path.join(output_dir, 'cvc5')
                    shutil.copy2(cvc5_bin, output_path)
                    os.chmod(output_path, 0o755)
                    print(f"✅ Installed to: {output_path}")
                    return output_path
        
        print("❌ cvc5 binary not found in archive")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Download latest CVC5 binary from GitHub releases')
    parser.add_argument('output_dir', nargs='?', default=os.path.join(os.path.expanduser('~'), '.local', 'bin'),
                       help='Output directory (default: ~/.local/bin)')
    args = parser.parse_args()
    
    install_unzip()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Get GitHub token from environment variable (set by GitHub Actions)
    github_token = os.environ.get('GITHUB_TOKEN')
    
    print("🔍 Finding latest CVC5 release...")
    release = get_latest_release(github_token)
    tag = release['tag_name']
    print(f"📦 Latest release: {tag}")
    
    binary_url = find_linux_binary(release['assets'])
    if not binary_url:
        print(f"❌ Linux x86_64 static binary not found in {tag}")
        sys.exit(1)
    
    binary_path = download_and_extract(binary_url, str(output_dir), github_token)
    
    # Verify
    result = subprocess.run([binary_path, '--version'], capture_output=True, text=True, check=False)
    if result.returncode == 0:
        print(result.stdout.strip())

if __name__ == "__main__":
    main()
