import os
import re
import math
import time
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

# --- Performance Config ---
PROGRESS_INTERVAL = 100  # Update every 100 files
SKIPPED_DIRS = {'.git', 'node_modules', 'vendor', 'dist', 'build', '__pycache__'}  # Skip irrelevant dirs
SKIPPED_EXTS = {  # Only skip known binary files
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.psd', '.ico', '.svg',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.tar',
    '.gz', '.7z', '.exe', '.dll', '.so', '.o', '.a', '.class', '.jar', '.war'
}

# --- Global Deduplication ---
seen_outputs = defaultdict(set)

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
def normalize_github_url(url):
    """Extract github.com/username from various GitHub URL formats"""
    patterns = [
        r"github\.com/([a-zA-Z0-9-]+)(?:/.*)?",
        r"git@github\.com:([a-zA-Z0-9-]+)(?:/.*)?(?:\.git)?",
        r"git://github\.com/([a-zA-Z0-9-]+)(?:/.*)?(?:\.git)?",
        r"git\+https://github\.com/([a-zA-Z0-9-]+)(?:/.*)?(?:\.git)?"
    ]
    for pattern in patterns:
        match = re.search(pattern, url, re.IGNORECASE)
        if match:
            username = match.group(1).lower()
            if username in {'github', 'user', 'dummy', 'dymmy', 'articles'}:
                return None
            if len(username) < 2 or not re.match(r'^[a-zA-Z0-9-]+$', username):
                return None
            return f"github.com/{username}"
    # Handle github.io by extracting the username
    if url.lower().startswith("http") and ".github.io" in url.lower():
        match = re.match(r"https?://([a-zA-Z0-9-]+)\.github\.io(?:/.*)?", url, re.IGNORECASE)
        if match:
            username = match.group(1).lower()
            if username in {'github', 'user', 'dummy', 'dymmy', 'articles'}:
                return None
            if len(username) < 2 or not re.match(r'^[a-zA-Z0-9-]+$', username):
                return None
            return f"github.com/{username}"
    return None

def normalize_url(url):
    """Extract base domain for generic URLs, full path for GitHub"""
    if 'github.com' in url.lower() or '.github.io' in url.lower():
        return normalize_github_url(url)
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc.split(':')[0].lower()
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

# --- URL Filtering Function ---
def is_valid_url(url):
    """Check if URL is public and valid"""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        netloc = parsed.netloc.split(':')[0].lower()
        if any(netloc.startswith(prefix) for prefix in ("localhost", "127.", "192.168.", "10.", "::1")):
            return False
        excluded_domains = {
            "youtube.com", "google.com", "facebook.com", "twitter.com", "x.com",
            "linkedin.com", "instagram.com", "wikipedia.org", "example.com",
            "docs.github.com", "help.github.com", "noreply.github.com", "api.github.com",
            "raw.githubusercontent.com", "gitlab.io", "surge.sh", "vercel.app",
            "netlify.app", "firebaseapp.com", "s3.amazonaws.com", "storage.googleapis.com",
            "digitaloceanspaces.com", "wasabisys.com", "backblazeb2.com", "npmjs.org",
            "pypi.org", "docker.com", "rubygems.org", "nuget.org", "go.dev",
            "packagist.org", "herokuapp.com", "allrecipes.com", "postgresql.org",
            "fedoraproject.org", "apache.org", "js.cloudflare.com", "cdnjs.cloudflare.com",
            "www.gitignore.io", "intellij-support.jetbrains.com", "pdm-project.org",
            "abstra.io", "files.pythonhosted.org"
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

# --- Enhanced Regex Patterns ---
public_patterns = {
    "github_repos": re.compile(r"(?:https?://|git@|git://|git\+https://)github\.com[/:]([a-zA-Z0-9-]+/[a-zA-Z0-9-]+)(?:\.git)?", re.IGNORECASE),
    "github_pages_current": re.compile(r"([a-zA-Z0-9-]+\.github\.io(?:/[a-zA-Z0-9-]+)?)(?:/|$|[^\s)\]\'\";>])", re.IGNORECASE),
    "npm_github_urls": re.compile(r"git\+https://github\.com/([a-zA-Z0-9-]+/[a-zA-Z0-9-]+)(?:\.git)?", re.IGNORECASE),
    "heroku": re.compile(r"([a-zA-Z0-9-]+\.herokuapp\.com)(?:/|$)", re.IGNORECASE),
    "gitlab_pages": re.compile(r"([a-zA-Z0-9-]+\.gitlab\.io)(?:/|$)", re.IGNORECASE),
    "surge_sh": re.compile(r"([a-zA-Z0-9-]+\.surge\.sh)(?:/|$)", re.IGNORECASE),
    "vercel": re.compile(r"([a-zA-Z0-9-]+\.vercel\.app)(?:/|$)", re.IGNORECASE),
    "netlify": re.compile(r"([a-zA-Z0-9-]+\.netlify\.(?:app|com))(?:/|$)", re.IGNORECASE),
    "firebase": re.compile(r"([a-zA-Z0-9-]+\.firebaseapp\.com)(?:/|$)", re.IGNORECASE),
    "aws_s3": re.compile(r"([a-zA-Z0-9-]+\.s3(?:[.-](?:us|eu|ap|sa|ca|af|me)-[a-z0-9]-\d)?\.amazonaws\.com)(?:/|$)", re.IGNORECASE),
    "google_storage": re.compile(r"([a-zA-Z0-9-]+\.storage\.googleapis\.com)(?:/|$)", re.IGNORECASE),
    "digitalocean_spaces": re.compile(r"([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.digitaloceanspaces\.com)(?:/|$)", re.IGNORECASE),
    "wasabi": re.compile(r"([a-zA-Z0-9-]+\.s3\.wasabisys\.com)(?:/|$)", re.IGNORECASE),
    "backblaze": re.compile(r"([a-zA-Z0-9-]+\.s3\.[a-zA-Z0-9-]+\.backblazeb2\.com)(?:/|$)", re.IGNORECASE),
    "npm": re.compile(r"(registry\.npmjs\.org/[a-zA-Z0-9_-]+)(?:/|$)", re.IGNORECASE),
    "pypi": re.compile(r"(pypi\.org/project/[a-zA-Z0-9_-]+)(?:/|$)", re.IGNORECASE),
    "docker": re.compile(r"(hub\.docker\.com/r/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)(?:/|$)", re.IGNORECASE),
    "rubygems": re.compile(r"(rubygems\.org/gems/[a-zA-Z0-9_-]+)(?:/|$)", re.IGNORECASE),
    "nuget": re.compile(r"(nuget\.org/packages/[a-zA-Z0-9._-]+)(?:/|$)", re.IGNORECASE),
    "go_modules": re.compile(r"(pkg\.go\.dev/[a-zA-Z0-9_./-]+)(?:/|$)", re.IGNORECASE),
    "composer": re.compile(r"(packagist\.org/packages/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)(?:/|$)", re.IGNORECASE),
    "aws_access_key": re.compile(r"\b(AKIA|AIDA|AROA|ASIA)[A-Z0-9]{16}\b"),
    "aws_secret_key": re.compile(r"(?i)\b(aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]?([a-zA-Z0-9/+]{40})['\"]?"),
    "aws_session_token": re.compile(r"\b(AQo|ASIA)[A-Za-z0-9/+]{200,400}\b"),
    "github_tokens": re.compile(r"\bgh(p|u|o|s|r|pat)_[a-zA-Z0-9]{36}\b"),
    "stripe_keys": re.compile(r"\b(sk|pk)_(live|test)_[a-zA-Z0-9]{24}\b"),
    "paypal_tokens": re.compile(r"\b(access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32})\b"),
    "google_api": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "azure_key": re.compile(r"(?i)\b(accountkey|storagekey)\s*[:=]\s*['\"]?([a-zA-Z0-9+/]{44}={0,2})['\"]?"),
    "gcp_service_account": re.compile(r'"type"\s*:\s*"service_account".*?"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----', re.DOTALL),
    "twilio_keys": re.compile(r"\b(SK|AC)[a-fA-F0-9]{32}\b"),
    "slack_tokens": re.compile(r"\b(xox[baprs]-[a-zA-Z0-9-]{10,48})\b"),
    "slack_webhook": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"),
    "bearer_token": re.compile(r"bearer\s+[a-zA-Z0-9_\-\.=:/+]{20,800}", re.I),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_+/=]*\b"),
    "oauth_token": re.compile(r"\b(ya29\.[0-9A-Za-z\-_]+|1/[0-9A-Za-z\-_]{43,64})\b"),
    "api_key": re.compile(r"(?i)(?:^|[^.\w])(api[_-]?key|secret|token|credential|auth)[\s:=]+['\"]?([a-zA-Z0-9\-_=+/.]{20,100})['\"]?(?:\s|$)"),
    "password": re.compile(r"(?i)\b(pass(word|wd)?|pwd)[\s:=]+['\"]?([^\s]{8,})['\"]?"),
    "private_key": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----(?s:.+?)-----END"),
    "ssh_key": re.compile(r"ssh-(rsa|dss|ed25519) [A-Za-z0-9+/]+[=]{0,3}"),
    "mailgun_key": re.compile(r"\b(key-[0-9a-f]{32}|[0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8})\b"),
    "heroku_key": re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    "npm_token": re.compile(r"\bnpm_[a-zA-Z0-9]{36}\b"),
    "postgres_uri": re.compile(r"postgres(?:ql)?://[a-zA-Z0-9_%\-]+:[^@\s]+@[a-zA-Z0-9.-]+(?::\d+)?/[^?\s]+"),
    "generic_urls": re.compile(r"(https?://(?!localhost|127\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|::1)[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+[^\s)\]\'\";>]+)", re.IGNORECASE)
}

# --- Optimized Scanner ---
def scan_files(source_dir, source_type):
    secret_patterns = [
        "aws_access_key", "aws_secret_key", "aws_session_token", "github_tokens", "stripe_keys",
        "paypal_tokens", "google_api", "azure_key", "gcp_service_account", "twilio_keys",
        "slack_tokens", "slack_webhook", "bearer_token", "jwt", "oauth_token", "api_key",
        "password", "private_key", "ssh_key", "mailgun_key", "heroku_key", "npm_token",
        "postgres_uri"
    ]
    processed_files = 0
    start_time = time.time()

    with open(hist_file_path, 'a') as hist_file, open(errors_file, 'a') as err_file:
        print(f"\nScanning {source_type.upper()} repos...")
        for root, dirs, files in os.walk(source_dir):
            # Skip unwanted directories by modifying the dirs list in place
            dirs[:] = [d for d in dirs if d not in SKIPPED_DIRS]
            repo_name = os.path.basename(root).replace("/", "_")
            print(f"Starting repo: {repo_name}")
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, source_dir)
                
                # Skip based on extension
                if os.path.splitext(file)[1].lower() in SKIPPED_EXTS:
                    continue
                
                processed_files += 1
                print(f"Processing: {repo_name}/{file}")
                if processed_files % PROGRESS_INTERVAL == 0:
                    elapsed = time.time() - start_time
                    print(f"Processed {processed_files} files in {elapsed:.2f} seconds")
                
                file_start_time = time.time()
                try:
                    # Check if file is text-readable before processing
                    with open(file_path, 'rb') as f:
                        first_chunk = f.read(1024)  # Read first 1KB to check
                    try:
                        content = first_chunk.decode('utf-8')
                        # If decoding works, proceed with chunked reading
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = ""
                            while chunk := f.read(8192):  # 8KB chunks
                                content += chunk
                    except UnicodeDecodeError:
                        print(f"Skipping non-text file: {file_path}")
                        continue
                    
                    # Check if processing takes too long (3 minutes = 180 seconds)
                    if time.time() - file_start_time > 180:
                        print(f"Skipping {file_path} due to 3-minute timeout")
                        continue
                    
                    patterns_to_apply = public_patterns if source_type == 'public' else {
                        k: v for k, v in public_patterns.items() if k in secret_patterns
                    }
                    output_dir = output_dirs['public'] if source_type == 'public' else output_dirs['archived_secrets']
                    
                    for pattern_name, pattern in patterns_to_apply.items():
                        matches = pattern.findall(content)
                        if not matches:
                            continue
                        if pattern_name in ["heroku", "aws_s3", "google_storage", "digitalocean_spaces", "wasabi", "backblaze", "gitlab_pages", "surge_sh", "vercel", "netlify", "firebase"]:
                            subdir = "cloud"
                        elif pattern_name in ["github_repos", "npm_github_urls", "github_pages_current"]:
                            subdir = "github"
                        elif pattern_name in ["npm", "pypi", "docker", "rubygems", "nuget", "go_modules", "composer"]:
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
                                original_match = match if not isinstance(match, tuple) else match[0]
                                if pattern_name == "github_pages_current":
                                    # Normalize to github.com/username and write to github_repos.txt
                                    normalized = normalize_github_url(original_match)
                                    if normalized and normalized.startswith("github.com/") and normalized not in seen_outputs[output_file]:
                                        seen_outputs[output_file].add(normalized)
                                        out_file.write(f"{normalized}\n")
                                elif pattern_name in ["github_repos", "npm_github_urls"]:
                                    if isinstance(match, tuple):
                                        username = match[0].split('/')[0] if len(match) > 0 and '/' in match[0] else None
                                        if username:
                                            output_str = f"github.com/{username}"
                                        else:
                                            output_str = match[0]
                                    else:
                                        output_str = match
                                        if '/' in match:
                                            username = match.split('/')[0]
                                            output_str = f"github.com/{username}"
                                        else:
                                            output_str = match
                                    if output_str not in seen_outputs[output_file]:
                                        seen_outputs[output_file].add(output_str)
                                        out_file.write(f"{output_str}\n")
                                else:
                                    normalized = normalize_url(original_match)
                                    if normalized and normalized not in seen_outputs[output_file]:
                                        seen_outputs[output_file].add(normalized)
                                        out_file.write(f"{normalized}\n")
                                
                                # Write original match to history for tracking
                                hist_file.write(f"{source_type}/{repo_name}:{relative_path}:{pattern_name}:{original_match}\n")
                except Exception as e:
                    err_file.write(f"Error reading {file_path}: {e}\n")

# --- Post-Process urls.txt to Move GitHub URLs ---
def post_process_urls():
    urls_file = os.path.join(output_dirs['public'], 'urls', 'generic_urls.txt')
    github_repos_file = os.path.join(output_dirs['public'], 'github', 'github_repos.txt')
    temp_urls_file = os.path.join(output_dirs['public'], 'urls', 'temp_urls.txt')
    
    if not os.path.exists(urls_file):
        return
    
    github_urls = set()
    non_github_urls = []
    
    # Read urls.txt and filter GitHub-related URLs
    with open(urls_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            url = line.strip()
            normalized = normalize_github_url(url)
            if normalized and normalized.startswith("github.com/"):
                github_urls.add(normalized)
            elif url:
                non_github_urls.append(url)
    
    # Append GitHub URLs to github_repos.txt
    if github_urls:
        os.makedirs(os.path.dirname(github_repos_file), exist_ok=True)
        with open(github_repos_file, 'a', encoding='utf-8') as f:
            for url in sorted(github_urls):
                if url not in seen_outputs[github_repos_file]:
                    seen_outputs[github_repos_file].add(url)
                    f.write(f"{url}\n")
    
    # Rewrite urls.txt with non-GitHub URLs
    with open(temp_urls_file, 'w', encoding='utf-8') as f:
        for url in non_github_urls:
            f.write(f"{url}\n")
    
    # Replace original urls.txt with temp file
    os.replace(temp_urls_file, urls_file)

# --- Main Execution ---
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

if os.path.exists(public_dir):
    scan_files(public_dir, 'public')
if os.path.exists(archived_dir):
    scan_files(archived_dir, 'archived')

# Run post-processing to clean up urls.txt
post_process_urls()

print("Scanning complete!")
print(f"Results in: {', '.join([os.path.join(output_dir, subdir) for output_dir in output_dirs.values() for subdir in subdirs if os.path.exists(os.path.join(output_dir, subdir))])}")
print(f"History in: {hist_file_path}")
print(f"Errors in: {errors_file}")
