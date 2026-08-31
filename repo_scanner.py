"""Hyperion Security Engine — repository scanner for GitHub projects.

This module extends scanner.py and dependency_check.py to scan entire GitHub
repositories for security vulnerabilities in source code and dependencies.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from dependency_check import check_dependencies, parse_requirements
from scanner import scan_source


def _handle_remove_readonly(func, path, exc):
    """Handle PermissionError when removing files on Windows.
    
    This is commonly encountered with git repositories where files in .git/objects
    may have read-only attributes that prevent deletion.
    """
    # Clear the read-only attribute and retry
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _is_github_repo_url(url: str) -> bool:
    """Validate that a URL looks like a GitHub repository URL.
    
    Accepts formats like:
    - https://github.com/user/repo
    - https://github.com/user/repo/
    - git@github.com:user/repo.git
    
    Rejects anything that doesn't clearly look like a GitHub repo URL.
    """
    if not url or not isinstance(url, str):
        return False
    
    # Normalize the URL for easier checking
    url = url.strip()
    
    # HTTPS GitHub URL pattern
    https_pattern = r'^https://github\.com/[^/]+/[^/]+/?$'
    if re.match(https_pattern, url, re.IGNORECASE):
        return True
    
    # SSH/git URL pattern
    ssh_pattern = r'^git@github\.com:[^/]+/[^/]+\.git$'
    if re.match(ssh_pattern, url, re.IGNORECASE):
        return True
    
    # HTTPS with .git suffix
    https_git_pattern = r'^https://github\.com/[^/]+/[^/]+\.git/?$'
    if re.match(https_git_pattern, url, re.IGNORECASE):
        return True
    
    return False


def scan_repository(github_url: str) -> dict[str, Any]:
    """Scan a full GitHub repository for security vulnerabilities.
    
    Args:
        github_url: A GitHub repository URL (validated to be GitHub-only)
        
    Returns:
        A dictionary with keys:
        - scan_findings: List of vulnerability findings from source code scanning
        - dep_findings: List of vulnerability findings from dependency checking
        - files_scanned: Number of Python files successfully scanned
        - repo_url: The original repository URL
        - error: Error message if scanning failed, None if successful
        - notes: Optional notes about limitations (e.g., file count cap hit)
    """
    # Initialize result structure
    result: dict[str, Any] = {
        "scan_findings": [],
        "dep_findings": [],
        "files_scanned": 0,
        "repo_url": github_url,
        "error": None,
        "notes": None,
    }
    
    # Validate URL
    if not _is_github_repo_url(github_url):
        result["error"] = f"Invalid GitHub repository URL: {github_url}"
        return result
    
    # Create temporary directory for cloning
    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp(prefix="hyperion_scan_")
        repo_path = Path(temp_dir) / "repo"
        
        # Clone the repository with timeout and depth limit
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", github_url, str(repo_path)],
                check=True,
                capture_output=True,
                timeout=30,  # 30 second hard timeout
            )
        except subprocess.TimeoutExpired:
            result["error"] = "Repository clone timed out after 30 seconds"
            return result
        except subprocess.CalledProcessError as e:
            result["error"] = f"Failed to clone repository: {e.stderr.decode('utf-8', errors='ignore').strip()}"
            return result
        
        # Check if we got anything
        if not repo_path.exists() or not any(repo_path.iterdir()):
            result["error"] = "Cloned repository appears to be empty"
            return result
        
        # Walk the repository to find Python files
        py_files: list[Path] = []
        skip_dirs = {"venv", "__pycache__", ".git", "node_modules"}
        
        for root, dirs, files in os.walk(repo_path):
            # Modify dirs in-place to skip unwanted directories
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for file in files:
                if file.endswith(".py"):
                    file_path = Path(root) / file
                    py_files.append(file_path)
        
        # Apply file count limit
        MAX_FILES = 500
        if len(py_files) > MAX_FILES:
            py_files = py_files[:MAX_FILES]
            result["notes"] = f"File count capped at {MAX_FILES} files; {len(py_files)} files scanned"
        
        # Scan each Python file
        MAX_FILE_SIZE = 1024 * 1024  # 1MB
        for file_path in py_files:
            try:
                # Check file size
                file_size = file_path.stat().st_size
                if file_size > MAX_FILE_SIZE:
                    # Skip oversized files but continue with others
                    continue
                
                # Read file content
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                
                # Get relative path from repo root for reporting
                relative_path = file_path.relative_to(repo_path)
                
                # Scan the source code
                findings = scan_source(content, filename=str(relative_path))
                
                # Add findings to results
                result["scan_findings"].extend(findings)
                result["files_scanned"] += 1
                
            except (OSError, UnicodeDecodeError):
                # Skip files that can't be read, but continue scanning
                continue
            except Exception:
                # Skip files that cause unexpected errors, but continue scanning
                continue
        
        # Check for requirements.txt in repository root
        requirements_files = [
            repo_path / "requirements.txt",
            repo_path / "requirements" / "base.txt",
            repo_path / "requirements" / "requirements.txt",
        ]
        
        req_path = None
        for req_file in requirements_files:
            if req_file.is_file():
                req_path = req_file
                break
        
        # If we found a requirements file, check dependencies
        if req_path:
            try:
                dep_findings = check_dependencies(str(req_path))
                result["dep_findings"] = dep_findings
            except Exception:
                # If dependency checking fails, we still return source scan results
                # but note the dependency check failure
                if result["notes"]:
                    result["notes"] += "; dependency check failed"
                else:
                    result["notes"] = "dependency check failed"
        
        # Success - no error
        result["error"] = None
        
    except Exception as e:
        # Catch any unexpected errors and return them gracefully
        result["error"] = f"Unexpected error during scanning: {str(e)}"
    
    finally:
        # ALWAYS clean up the temporary directory
        if temp_dir and Path(temp_dir).exists():
            try:
                if sys.version_info >= (3, 12):
                    shutil.rmtree(temp_dir, onexc=_handle_remove_readonly)
                else:
                    shutil.rmtree(temp_dir, onerror=_handle_remove_readonly)
            except Exception:
                # Best effort cleanup - if we can't remove it, we note it but don't fail
                if result["notes"]:
                    result["notes"] += "; warning: failed to cleanup temporary directory"
                else:
                    result["notes"] = "warning: failed to cleanup temporary directory"
    
    return result