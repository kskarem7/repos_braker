import os
import re
import shutil
import math
from urllib.parse import urlparse
from collections import defaultdict

# --- User Configuration ---
base_dir = input("Enter folder name (e.g., github.com_projectrepo): ").strip()
public_dir = os.path.join(os.getcwd(), base_dir, 'phase_1-github.com_repos', 'public')
priority_dir = os.path.join(os.getcwd(), base_dir, 'priority_1', 'p1_repos')
output_dirs = {
    'p1_1': os.path.join(os.getcwd(), base_dir, 'priority_1', 'p1_1_exact_filenames'),
    'p1_2': os.path.join(os.getcwd(), base_dir, 'priority_1', 'p1_2_general_filenames'),
    'p1_3': os.path.join(os.getcwd(), base_dir, 'priority_1', 'p1_3_yml_sh_yaml')
}
subdirs = ['cloud', 'github', 'pkgs', 'secrets', 'urls']
hist_file_path = os.path.join(os.getcwd(), base_dir, 'historical.txt')
errors_file = os.path.join(os.getcwd(), base_dir, 'errors.txt')

# Create priority_dir (but not output subdirs yet)
os.makedirs(priority_dir, exist_ok=True)

# --- Global Deduplication Tracking ---
seen_outputs = defaultdict(set)  # {output_file_path: set(unique_identifiers)}
github_usernames = set()  # Track GitHub usernames across all files

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
            return match.group(1).lower()  # Return lowercase username
    return None

def normalize_url(url):
    """Extract just the domain for URLs"""
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc.split(':')[0]  # Just the domain (e.g., example.com)
    except:
        pass
    return url

# --- Improved Secret Validation ---
def is_valid_secret(pattern_name, secret):
    """Less strict validation for passwords and secrets"""
    secret = str(secret).strip()
    
    # Skip empty strings
    if not secret:
        return False
        
    # Common false positives
    false_positives = {
        "example", "test", "demo", "sample", "placeholder",
        "changeme", "password", "secret", "token", "key",
        "your-", "enter-", "put-", "dummy", "mock", "fake"
    }
    
    # Check against false positives (case insensitive)
    secret_lower = secret.lower()
    if any(fp in secret_lower for fp in false_positives):
        return False
    
    # Special handling for passwords
    if pattern_name == "passwords":
        return len(secret) >= 6  # Only require minimum length
    
    # For other secrets, basic length check
    return len(secret) >= 8

# --- Private Filters for Priority Files ---
private_filters = {
    'p1_1': re.compile(r'^(\.github/workflows/.*\.ya?ml|\.gitlab-ci\.ya?ml|\.travis\.ya?ml|bitbucket-pipelines\.ya?ml|buildspec\.ya?ml|\.circleci/config\.ya?ml|Jenkinsfile|azure-pipelines\.ya?ml)$'),
    'p1_2': re.compile(r'.*(gitlab|travis|bitbucket|circleci|jenkins|azure|workflow|pipeline|ci|cd|deploy|build).*\.(ya?ml|json)$'),
    'p1_3': re.compile(r'.*\.(yml|yaml|sh)$')
}

# --- Enhanced Regex Patterns ---
public_patterns = {
    # GitHub Patterns - only captures username
    "github_repos": re.compile(r"(?:https?://|git@|git://|git\+https://)github\.com[/:]([a-zA-Z0-9-]+)(?:/|$)"),
    "npm_github_urls": re.compile(r"git\+https://github\.com/([a-zA-Z0-9-]+)(?:/|$)"),
    
    # Other patterns
    "github_pages_current": re.compile(r"([a-zA-Z0-9-]+\.github\.io)(?:/|$)"),
    "github_pages_deprecated": re.compile(r"([a-zA-Z0-9-]+\.github\.com)(?:/|$)"),
    "github_io_suspicious": re.compile(r"(github\.io/[a-zA-Z0-9-]+)(?:/|$)"),
    "heroku": re.compile(r"([a-zA-Z0-9-]+\.herokuapp\.com)(?:/|$)"),
    "gitlab_pages": re.compile(r"([a-zA-Z0-9-]+\.gitlab\.io)(?:/|$)"),
    "surge_sh": re.compile(r"([a-zA-Z0-9-]+\.surge\.sh)(?:/|$)"),
    "vercel": re.compile(r"([a-zA-Z0-9-]+\.vercel\.app)(?:/|$)"),
    "netlify": re.compile(r"([a-zA-Z0-9-]+\.netlify\.(?:app|com))(?:/|$)"),
    "firebase": re.compile(r"([a-zA-Z0-9-]+\.firebaseapp\.com)(?:/|$)"),
    "aws_s3": re.compile(r"([a-zA-Z0-9-]+\.s3(?:[.-](?:us|eu|ap|sa|ca|af|me)-[a-z]-\d)?\.amazonaws\.com)(?:/|$)"),
    "google_storage": re.compile(r"([a-zA-Z0-9-]+\.storage\.googleapis\.com)(?:/|$)"),
    "digitalocean_spaces": re.compile(r"([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.digitaloceanspaces\.com)(?:/|$)"),
    "wasabi": re.compile(r"([a-zA-Z0-9-]+\.s3\.wasabisys\.com)(?:/|$)"),
    "backblaze": re.compile(r"([a-zA-Z0-9-]+\.s3\.[a-zA-Z0-9-]+\.backblazeb2\.com)(?:/|$)"),
    "npm": re.compile(r"(registry\.npmjs\.org/[a-zA-Z0-9_-]+)(?:/|$)"),
    "pypi": re.compile(r"(pypi\.org/project/[a-zA-Z0-9_-]+)(?:/|$)"),
    "docker": re.compile(r"(hub\.docker\.com/r/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)(?:/|$)"),
    "rubygems": re.compile(r"(rubygems\.org/gems/[a-zA-Z0-9_-]+)(?:/|$)"),
    "nuget": re.compile(r"(nuget\.org/packages/[a-zA-Z0-9._-]+)(?:/|$)"),
    "go_modules": re.compile(r"(pkg\.go\.dev/[a-zA-Z0-9_./-]+)(?:/|$)"),
    "composer": re.compile(r"(packagist\.org/packages/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)(?:/|$)"),
    "aws_keys": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    "github_tokens": re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b"),
    "github_oauth": re.compile(r"\b(gho_[0-9a-zA-Z]{36})\b"),
    "stripe_keys": re.compile(r"\b(sk_live_[0-9a-zA-Z]{24})\b"),
    "google_api": re.compile(r"\b(AIza[0-9A-Za-z-_]{35})\b"),
    "twilio_keys": re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
    "slack_tokens": re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
    "bearer_tokens": re.compile(r"bearer\s+([a-zA-Z0-9_\-\.=:_\+\/]{20,60})"),
    "api_keys": re.compile(r"(?i)\bapi[_-]?key[\s:=]+['\"]?([0-9a-zA-Z\-_.]{10,60})['\"]?"),
    "secrets": re.compile(r"(?i)\b(secret|token)[\s:=]+['\"]?([0-9a-zA-Z\-_.]{10,60})['\"]?"),
    "passwords": re.compile(r"(?i)\b(password|pwd|pass)[\s:=]+['\"]?([^\s]{6,})['\"]?"),
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
            "rubygems.org", "nuget.org", "go.dev", "packagist.org", "herokuapp.com"
        }
        domain_parts = netloc.split('.')
        for i in range(len(domain_parts)):
            test_domain = '.'.join(domain_parts[i:])
            if test_domain in excluded_domains:
                return False
        if parsed.scheme in ("file", "data", "javascript"):
            return False
        return True
    except:
        return False

# --- Step 1: Scan public/ for priority files ---
public_files = []
for root, _, files in os.walk(public_dir):
    repo_name = os.path.basename(root)
    for file in files:
        file_path = os.path.join(root, file)
        relative_path = os.path.relpath(file_path, public_dir)
        for filter_name, pattern in private_filters.items():
            if pattern.search(relative_path):
                public_files.append((file_path, filter_name, repo_name))
                break

# --- Step 2: Check if p1_repos exists and decide action ---
new_files_moved = False
p1_files = []
for root, _, files in os.walk(priority_dir):
    for file in files:
        p1_files.append(file)

if os.path.exists(priority_dir) and p1_files and public_files:
    choice = input(f"Found {len(public_files)} priority files in public/. Rescan and move (m) or skip to regex (r)? ").lower()
    if choice == 'm':
        new_files_moved = True
        # Clear output files and historical
        for output_dir in output_dirs.values():
            for subdir in subdirs:
                subdir_path = os.path.join(output_dir, subdir)
                if os.path.exists(subdir_path):
                    for file in os.listdir(subdir_path):
                        file_path = os.path.join(subdir_path, file)
                        if os.path.exists(file_path):
                            open(file_path, 'w').close()
        if os.path.exists(hist_file_path):
            open(hist_file_path, 'w').close()
else:
    new_files_moved = True
    # Clear output files and historical
    for output_dir in output_dirs.values():
        for subdir in subdirs:
            subdir_path = os.path.join(output_dir, subdir)
            if os.path.exists(subdir_path):
                for file in os.listdir(subdir_path):
                    file_path = os.path.join(subdir_path, file)
                    if os.path.exists(file_path):
                        open(file_path, 'w').close()
    if os.path.exists(hist_file_path):
        open(hist_file_path, 'w').close()

# --- Step 3: Move priority files to repo-specific folders ---
if new_files_moved:
    for file_path, filter_name, repo_name in public_files:
        target_repo_dir = os.path.join(priority_dir, repo_name.replace("/", "_"))
        os.makedirs(target_repo_dir, exist_ok=True)
        shutil.move(file_path, os.path.join(target_repo_dir, os.path.basename(file_path)))

# --- Step 4: Enhanced Scanning of moved files ---
with open(hist_file_path, 'a') as hist_file, open(errors_file, 'a') as err_file:
    for root, _, files in os.walk(priority_dir):
        repo_name = os.path.basename(root)
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, priority_dir)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Determine filter type
                    filter_type = None
                    for filter_name, pattern in private_filters.items():
                        if pattern.search(os.path.join(repo_name, relative_path)):
                            filter_type = filter_name
                            break
                    if not filter_type:
                        continue

                    output_dir = output_dirs[filter_type]
                    for pattern_name, pattern in public_patterns.items():
                        matches = pattern.findall(content)
                        if not matches:
                            continue
                        
                        # Determine output subfolder
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
                                    match_str = match[0] if len(match) == 1 else match[1]
                                else:
                                    match_str = match
                                
                                # Handle different pattern types
                                if pattern_name in ["github_repos", "npm_github_urls"]:
                                    username = extract_github_user(match_str) or match_str.split('/')[0]
                                    output_str = f"github.com/{username.lower()}"
                                elif pattern_name == "generic_urls":
                                    output_str = normalize_url(match_str)
                                else:
                                    output_str = match_str
                                
                                # Skip if invalid URL or secret
                                if pattern_name == "generic_urls" and not is_valid_url(match_str):
                                    continue
                                if pattern_name in ["aws_keys", "github_tokens", "github_oauth", 
                                                   "stripe_keys", "google_api", "twilio_keys", 
                                                   "slack_tokens", "bearer_tokens", "api_keys", 
                                                   "secrets", "passwords"] and not is_valid_secret(pattern_name, match_str):
                                    continue
                                
                                # Write to output file if not seen
                                if output_str.lower() not in seen_outputs[output_file]:
                                    seen_outputs[output_file].add(output_str.lower())
                                    out_file.write(f"{output_str}\n")
                                
                                # Always write full match to historical
                                hist_file.write(f"{repo_name}:{relative_path}:{pattern_name}:{match_str}\n")
            except Exception as e:
                err_file.write(f"Error reading {file_path}: {e}\n")

print("Scanning complete!")
print(f"Results in: {', '.join([os.path.join(output_dir, subdir) for output_dir in output_dirs.values() for subdir in subdirs])}")
print(f"History in: {hist_file_path}")
print(f"Errors in: {errors_file}")
