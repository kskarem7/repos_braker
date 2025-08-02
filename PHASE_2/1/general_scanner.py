import os
import re
import math
from urllib.parse import urlparse
from collections import defaultdict

# --- User Configuration ---
base_dir = input("Enter folder name (e.g., github.com_projectrepo): ").strip()
public_dir = os.path.join(os.getcwd(), base_dir, 'phase_1-github.com_repos', 'public')
archived_dir = os.path.join(os.getcwd(), base_dir, 'phase_1-github.com_repos', 'archived')
output_dirs = {
    'public': os.path.join(os.getcwd(), base_dir, 'phase_2.1', 'general_scan', 'public'),
    'archived_secrets': os.path.join(os.getcwd(), base_dir, 'phase_2.1', 'general_scan', 'archived_secrets')
}
subdirs = ['cloud', 'github', 'pkgs', 'secrets', 'urls']
hist_file_path = os.path.join(os.getcwd(), base_dir, 'historical.txt')
errors_file = os.path.join(os.getcwd(), base_dir, 'errors.txt')

# --- Global Deduplication Tracking ---
seen_outputs = defaultdict(set)  # {output_file_path: set(unique_identifiers)}

# --- Entropy Check for Secrets ---
def shannon_entropy(text):
    """Calculate Shannon entropy to filter low-entropy secrets"""
    if not text:
        return 0
    entropy = 0
    for char in set(text):
        p = text.count(char) / len(text)
        entropy -= p * math.log2(p)
    return entropy

# --- Normalization Functions ---
def extract_github_user(url):
    """Extract just the username from GitHub URLs"""
    patterns = [
        r"github\.com/([a-zA-Z0-9-]+)/[a-zA-Z0-9-]+",
        r"git@github\.com:([a-zA-Z0-9-]+)/[a-zA-Z0-9-]+",
        r"git://github\.com/([a-zA-Z0-9-]+)/[a-zA-Z0-9-]+",
        r"git\+https://github\.com/([a-zA-Z0-9-]+)/[a-zA-Z0-9-]+"
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None

def normalize_github_url(url):
    """Extract github.com/user/repo from various GitHub URL formats"""
    patterns = [
        r"github\.com/([a-zA-Z0-9-]+/[a-zA-Z0-9-]+)",
        r"git@github\.com:([a-zA-Z0-9-]+/[a-zA-Z0-9-]+)(?:\.git)?",
        r"git://github\.com/([a-zA-Z0-9-]+/[a-zA-Z0-9-]+)(?:\.git)?",
        r"git\+https://github\.com/([a-zA-Z0-9-]+/[a-zA-Z0-9-]+)(?:\.git)?"
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return f"github.com/{match.group(1)}"
    return url

def normalize_url(url):
    """Extract base domain for generic URLs, full path for GitHub"""
    if 'github.com' in url:
        return normalize_github_url(url)
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc.split(':')[0]  # Just the domain (e.g., opencollective.com)
    except:
        pass
    return url

# --- Improved Secret Validation ---
def is_valid_secret(pattern_name, secret):
    """Filter out common false positives and low-entropy secrets"""
    secret = str(secret).strip().lower()
    if pattern_name in ["api_keys", "secrets", "passwords"]:
        if shannon_entropy(secret) < 3.0:
            return False
    false_positives = {
        "aiven_authentication_token", "enter-your-token-here", "intelligence-gathering",
        "quarkus.kubernetes", "authentication_token", "your-api-key-here",
        "example_password", "placeholder", "dummy_value", "test_token",
        "change-me", "put-your-key-here"
    }
    if any(fp in secret for fp in false_positives):
        return False
    return True

# --- Enhanced Regex Patterns ---
public_patterns = {
    # GitHub Patterns
    "github_repos": re.compile(r"(?:https?://|git@|git://|git\+https://)github\.com[/:]([a-zA-Z0-9-]+/[a-zA-Z0-9-]+)(?:\.git)?"),
    "github_pages_current": re.compile(r"([a-zA-Z0-9-]+\.github\.io)(?:/|$)"),
    "github_pages_deprecated": re.compile(r"([a-zA-Z0-9-]+\.github\.com)(?:/|$)"),
    "github_io_suspicious": re.compile(r"(github\.io/[a-zA-Z0-9-]+)(?:/|$)"),
    "npm_github_urls": re.compile(r"git\+https://github\.com/([a-zA-Z0-9-]+/[a-zA-Z0-9-]+)(?:\.git)?"),
    
    # Cloud/Hosting Patterns
    "heroku": re.compile(r"([a-zA-Z0-9-]+\.herokuapp\.com)(?:/|$)"),
    "gitlab_pages": re.compile(r"([a-zA-Z0-9-]+\.gitlab\.io)(?:/|$)"),
    "surge_sh": re.compile(r"([a-zA-Z0-9-]+\.surge\.sh)(?:/|$)"),
    "vercel": re.compile(r"([a-zA-Z0-9-]+\.vercel\.app)(?:/|$)"),
    "netlify": re.compile(r"([a-zA-Z0-9-]+\.netlify\.(?:app|com))(?:/|$)"),
    "firebase": re.compile(r"([a-zA-Z0-9-]+\.firebaseapp\.com)(?:/|$)"),
    
    # Cloud Buckets
    "aws_s3": re.compile(r"([a-zA-Z0-9-]+\.s3(?:[.-](?:us|eu|ap|sa|ca|af|me)-[a-z]-\d)?\.amazonaws\.com)(?:/|$)"),
    "google_storage": re.compile(r"([a-zA-Z0-9-]+\.storage\.googleapis\.com)(?:/|$)"),
    "digitalocean_spaces": re.compile(r"([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.digitaloceanspaces\.com)(?:/|$)"),
    "wasabi": re.compile(r"([a-zA-Z0-9-]+\.s3\.wasabisys\.com)(?:/|$)"),
    "backblaze": re.compile(r"([a-zA-Z0-9-]+\.s3\.[a-zA-Z0-9-]+\.backblazeb2\.com)(?:/|$)"),
    
    # Package Managers
    "npm": re.compile(r"(registry\.npmjs\.org/[a-zA-Z0-9_-]+)(?:/|$)"),
    "pypi": re.compile(r"(pypi\.org/project/[a-zA-Z0-9_-]+)(?:/|$)"),
    "docker": re.compile(r"(hub\.docker\.com/r/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)(?:/|$)"),
    "rubygems": re.compile(r"(rubygems\.org/gems/[a-zA-Z0-9_-]+)(?:/|$)"),
    "nuget": re.compile(r"(nuget\.org/packages/[a-zA-Z0-9._-]+)(?:/|$)"),
    "go_modules": re.compile(r"(pkg\.go\.dev/[a-zA-Z0-9_./-]+)(?:/|$)"),
    "composer": re.compile(r"(packagist\.org/packages/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)(?:/|$)"),
    
    # Secrets
    "aws_keys": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    "github_tokens": re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b"),
    "github_oauth": re.compile(r"\b(gho_[0-9a-zA-Z]{36})\b"),
    "stripe_keys": re.compile(r"\b(sk_live_[0-9a-zA-Z]{24})\b"),
    "google_api": re.compile(r"\b(AIza[0-9A-Za-z-_]{35})\b"),
    "twilio_keys": re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
    "slack_tokens": re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
    "bearer_tokens": re.compile(r"bearer\s+([a-zA-Z0-9_\-\.=:_\+\/]{20,60})"),
    "api_keys": re.compile(r"(?i)\bapi[_-]?key[\s:=]+['\"]?([0-9a-zA-Z\-_.]{20,60})['\"]?"),
    "secrets": re.compile(r"(?i)\b(secret|token)[\s:=]+['\"]?([0-9a-zA-Z\-_.]{20,60})['\"]?"),
    "passwords": re.compile(r"(?i)\b(password|pwd|pass)[\s:=]+['\"]?([0-9a-zA-Z!@#$%^&*()\-+={}\[\]|:;\"'<>,.?/~`]{12,30})['\"]?"),
    
    # Generic URLs (Captures full URLs for historical, base domain for output)
    "generic_urls": re.compile(r"(https?://(?!localhost|127\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|::1)[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+[^\s)\]\'\";>]+)")
}

# --- URL Filtering Function ---
def is_valid_url(url):
    """Check if URL is public and valid"""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        netloc = parsed.netloc.split(':')[0]
        if any(netloc.startswith(prefix) for prefix in ("localhost", "127.", "192.168.", "10.", "::1")):
            return False
        excluded_domains = {
            "youtube.com", "google.com", "facebook.com", "twitter.com", "x.com",
            "linkedin.com", "instagram.com", "wikipedia.org", "example.com",
            "github.com", "github.io", "docs.github.com", "help.github.com",
            "noreply.github.com", "api.github.com", "raw.githubusercontent.com",
            "gitlab.io", "surge.sh", "vercel.app", "netlify.app", "firebaseapp.com",
            "s3.amazonaws.com", "storage.googleapis.com", "digitaloceanspaces.com",
            "wasabisys.com", "backblazeb2.com", "npmjs.org", "pypi.org", "docker.com",
            "rubygems.org", "nuget.org", "go.dev", "packagist.org", "herokuapp.com",
            "allrecipes.com", "postgresql.org", "fedoraproject.org", "apache.org",
            "js.cloudflare.com", "cdnjs.cloudflare.com", "www.gitignore.io",
            "intellij-support.jetbrains.com", "pdm-project.org", "abstra.io",
            "files.pythonhosted.org"
        }
        domain_parts = netloc.split('.')
        for i in range(len(domain_parts)):
            test_domain = '.'.join(domain_parts[i:])
            if test_domain in excluded_domains:
                return False
        if parsed.scheme in ("file", "data", "javascript"):
            return False
        if len(url) < 10 or any(s in url for s in ["filters:no_upscale(", "/Drinks", "/Cuisine/", "/Desserts/", ".js", ".css"]):
            return False
        return True
    except:
        return False

# ... existing code ...

# --- File Scanning Function ---
def scan_files(source_dir, source_type):
    secret_patterns = [
        "aws_keys", "github_tokens", "github_oauth", "stripe_keys", 
        "google_api", "twilio_keys", "slack_tokens", "bearer_tokens", 
        "api_keys", "secrets", "passwords"
    ]
    with open(hist_file_path, 'a') as hist_file, open(errors_file, 'a') as err_file:
        for root, _, files in os.walk(source_dir):
            repo_name = os.path.basename(root).replace("/", "_")
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, source_dir)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        patterns_to_apply = public_patterns if source_type == 'public' else {
                            k: v for k, v in public_patterns.items() if k in secret_patterns
                        }
                        output_dir = output_dirs['public'] if source_type == 'public' else output_dirs['archived_secrets']
                        for pattern_name, pattern in patterns_to_apply.items():
                            matches = pattern.findall(content)
                            if not matches:
                                continue
                            if pattern_name in ["heroku", "aws_s3", "google_storage", 
                                              "digitalocean_spaces", "wasabi", "backblaze", 
                                              "gitlab_pages", "surge_sh", "vercel", 
                                              "netlify", "firebase"]:
                                subdir = "cloud"
                            elif pattern_name in ["github_repos", "npm_github_urls", 
                                                "github_pages_current", "github_pages_deprecated", 
                                                "github_io_suspicious"]:
                                subdir = "github"
                            elif pattern_name in ["npm", "pypi", "docker", "rubygems", 
                                                "nuget", "go_modules", "composer"]:
                                subdir = "pkgs"
                            elif pattern_name == "generic_urls":
                                subdir = "urls"
                            else:
                                subdir = "secrets"
                            subdir_path = os.path.join(output_dir, subdir)
                            os.makedirs(subdir_path, exist_ok=True)
                            output_file = os.path.join(subdir_path, f"{pattern_name}.txt")
                            if output_file not in seen_outputs:
                                seen_outputs[output_file] = set()
                            with open(output_file, 'a') as out_file:
                                for match in matches:
                                    if isinstance(match, tuple):
                                        if pattern_name in ["github_repos", "npm_github_urls"]:
                                            # FIX: Capture only the username part
                                            username = match[0] if len(match) > 0 else None
                                            if username:
                                                output_str = f"github.com/{username}"
                                            else:
                                                output_str = match[0]  # Fallback
                                        else:
                                            match_str = match[0] if len(match) == 1 else match[1]
                                            output_str = match_str
                                    else:
                                        match_str = match
                                        # FIX: Extract username directly for GitHub patterns
                                        if pattern_name in ["github_repos", "npm_github_urls"]:
                                            if '/' in match_str:
                                                username = match_str.split('/')[0]
                                                output_str = f"github.com/{username}"
                                            else:
                                                output_str = match_str
                                        else:
                                            output_str = match_str
                                    
                                    if pattern_name == "generic_urls" and not is_valid_url(match_str):
                                        continue
                                    if pattern_name in secret_patterns and not is_valid_secret(pattern_name, match_str):
                                        continue
                                    
                                    # FIX: Handle GitHub patterns specifically
                                    if pattern_name in ["github_repos", "npm_github_urls", "github_io_suspicious"]:
                                        if output_str not in seen_outputs[output_file]:
                                            seen_outputs[output_file].add(output_str)
                                            out_file.write(f"{output_str}\n")
                                    else:
                                        normalized = normalize_url(match_str)
                                        if normalized not in seen_outputs[output_file]:
                                            seen_outputs[output_file].add(normalized)
                                            out_file.write(f"{normalized}\n")
                                    
                                    # Always write full match to historical
                                    hist_match = match_str if not isinstance(match, tuple) else match[0]
                                    hist_file.write(f"{source_type}/{repo_name}:{relative_path}:{pattern_name}:{hist_match}\n")
                except Exception as e:
                    err_file.write(f"Error reading {file_path}: {e}\n")

# ... rest of the code remains unchanged ...
# --- Step 1: Clear existing output files and historical log ---
for output_dir in output_dirs.values():
    for subdir in subdirs:
        subdir_path = os.path.join(output_dir, subdir)
        if os.path.exists(subdir_path):
            for file in os.listdir(subdir_path):
                file_path = os.path.join(subdir_path, file)
                if os.path.exists(file_path):
                    open(file_path, 'w').close()
seen_outputs.clear()
if os.path.exists(hist_file_path):
    open(hist_file_path, 'w').close()

# --- Step 2: Scan public/ and archived/ ---
if os.path.exists(public_dir):
    scan_files(public_dir, 'public')
if os.path.exists(archived_dir):
    scan_files(archived_dir, 'archived')

print("Scanning complete!")
print(f"Results in: {', '.join([os.path.join(output_dir, subdir) for output_dir in output_dirs.values() for subdir in subdirs if os.path.exists(os.path.join(output_dir, subdir))])}")
print(f"History in: {hist_file_path}")
print(f"Errors in: {errors_file}")
