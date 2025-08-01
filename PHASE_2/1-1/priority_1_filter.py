import os
import re
import shutil
from urllib.parse import urlparse

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

# --- Private Filters for Priority Files ---
private_filters = {
    'p1_1': re.compile(r'^(\.github/workflows/.*\.ya?ml|\.gitlab-ci\.ya?ml|\.travis\.ya?ml|bitbucket-pipelines\.ya?ml|buildspec\.ya?ml|\.circleci/config\.ya?ml|Jenkinsfile|azure-pipelines\.ya?ml)$'),
    'p1_2': re.compile(r'.*(gitlab|travis|bitbucket|circleci|jenkins|azure|workflow|pipeline|ci|cd|deploy|build).*\.(ya?ml|json)$'),
    'p1_3': re.compile(r'.*\.(yml|yaml|sh)$')
}

# --- Public Regex Patterns (Inspired by TruffleHog, Gitleaks, SecretFinder) ---
public_patterns = {
    # GitHub Patterns
    "github_repos": re.compile(r"https?://github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-]+"),
    "github_pages_current": re.compile(r"[a-zA-Z0-9-]+\.github\.io"),
    "github_pages_deprecated": re.compile(r"[a-zA-Z0-9-]+\.github\.com"),
    "github_io_suspicious": re.compile(r"github\.io/[a-zA-Z0-9-]+"),
    "npm_github_urls": re.compile(r"git\+https?://github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-]+"),
    
    # Cloud/Hosting Patterns
    "gitlab_pages": re.compile(r"[a-zA-Z0-9-]+\.gitlab\.io"),
    "surge_sh": re.compile(r"[a-zA-Z0-9-]+\.surge\.sh"),
    "vercel": re.compile(r"[a-zA-Z0-9-]+\.vercel\.app"),
    "netlify": re.compile(r"[a-zA-Z0-9-]+\.netlify\.app"),
    "firebase": re.compile(r"[a-zA-Z0-9-]+\.firebaseapp\.com"),
    
    # Cloud Buckets
    "aws_s3": re.compile(r"[a-zA-Z0-9-]+\.s3\.amazonaws\.com"),
    "google_storage": re.compile(r"[a-zA-Z0-9-]+\.storage\.googleapis\.com"),
    "digitalocean_spaces": re.compile(r"[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.digitaloceanspaces\.com"),
    "wasabi": re.compile(r"s3\.wasabisys\.com/[a-zA-Z0-9-]+"),
    "backblaze": re.compile(r"s3\.[a-zA-Z0-9-]+\.backblazeb2\.com/[a-zA-Z0-9-]+"),
    
    # Package Managers
    "npm": re.compile(r"registry\.npmjs\.org/[a-zA-Z0-9_-]+"),
    "pypi": re.compile(r"pypi\.org/project/[a-zA-Z0-9_-]+"),
    "docker": re.compile(r"hub\.docker\.com/r/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+"),
    "rubygems": re.compile(r"rubygems\.org/gems/[a-zA-Z0-9_-]+"),
    "nuget": re.compile(r"nuget\.org/packages/[a-zA-Z0-9._-]+"),
    "go_modules": re.compile(r"pkg\.go\.dev/[a-zA-Z0-9_./-]+"),
    "composer": re.compile(r"packagist\.org/packages/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+"),
    
    # Secrets
    "aws_keys": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_tokens": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "github_oauth": re.compile(r"gho_[0-9a-zA-Z]{36}"),
    "stripe_keys": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    "google_api": re.compile(r"AIza[0-9A-Za-z-_]{35}"),
    "twilio_keys": re.compile(r"SK[0-9a-fA-F]{32}"),
    "slack_tokens": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
    "bearer_tokens": re.compile(r"bearer\s+[a-zA-Z0-9_\-\.=:_\+\/]{20,60}"),
    "api_keys": re.compile(r"(?i)api[_-]?key[\s:=]+['\"]?([a-zA-Z0-9\-_.]{20,60})['\"]?"),
    "secrets": re.compile(r"(?i)(secret|token)[\s:=]+['\"]?([a-zA-Z0-9\-_.]{20,60})['\"]?"),
    "passwords": re.compile(r"(?i)(password|pwd|pass)[\s:=]+['\"]?([a-zA-Z0-9!@#$%^&*()\-_+={}\[\]|\\:;\"'<>,.?/~`]{6,30})['\"]?"),
    
    # Generic URLs (Last to avoid duplicates)
    "generic_urls": re.compile(r"https?://(?!localhost|127\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|::1)[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+[^\s)\]\'\";>]+")
}

# --- URL Filtering Function ---
def is_valid_url(url):
    """Check if URL is public, valid, and not covered by specific patterns"""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        # Skip internal IPs and domains
        if parsed.netloc.startswith(("localhost", "127.", "192.168.", "10.", "::1")):
            return False
        # Skip non-public TLDs
        if parsed.netloc.endswith((".local", ".internal", ".lan")):
            return False
        # Skip non-vulnerable and covered domains
        excluded_domains = {
            "youtube.com", "google.com", "facebook.com", "twitter.com", "x.com",
            "linkedin.com", "instagram.com", "wikipedia.org", "example.com",
            "github.com", "github.io", "docs.github.com", "help.github.com",
            "noreply.github.com", "api.github.com", "raw.githubusercontent.com",
            "gitlab.io", "surge.sh", "vercel.app", "netlify.app", "firebaseapp.com",
            "s3.amazonaws.com", "storage.googleapis.com", "digitaloceanspaces.com",
            "wasabisys.com", "backblazeb2.com", "npmjs.org", "pypi.org", "docker.com",
            "rubygems.org", "nuget.org", "go.dev", "packagist.org"
        }
        netloc = parsed.netloc.split(":")[0]  # Strip ports
        if netloc in excluded_domains or any(netloc.endswith("." + domain) for domain in excluded_domains):
            return False
        if parsed.scheme in ("file", "data", "javascript"):
            return False
        return True
    except:
        return False

# --- Step 1: Scan public/ for priority files ---
public_files = []
for root, _, files in os.walk(public_dir):
    repo_name = os.path.basename(root)  # Get original repo name (e.g., octocat/hello-world)
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
        target_repo_dir = os.path.join(priority_dir, repo_name.replace("/", "_"))  # e.g., octocat_hello-world
        os.makedirs(target_repo_dir, exist_ok=True)
        shutil.move(file_path, os.path.join(target_repo_dir, os.path.basename(file_path)))

# --- Step 4: Scan moved files for patterns ---
with open(hist_file_path, 'a') as hist_file, open(errors_file, 'a') as err_file:
    for root, _, files in os.walk(priority_dir):
        repo_name = os.path.basename(root)  # e.g., octocat_hello-world
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

                    # Create output subdirs only if matches are found
                    output_dir = output_dirs[filter_type]
                    matched_urls = set()
                    for pattern_name, pattern in public_patterns.items():
                        matches = pattern.findall(content)
                        if not matches:
                            continue
                        # Determine output subfolder
                        if pattern_name in ["aws_s3", "google_storage", "digitalocean_spaces", 
                                          "wasabi", "backblaze", "gitlab_pages", "surge_sh",
                                          "vercel", "netlify", "firebase"]:
                            subdir = "cloud"
                        elif pattern_name.startswith("github"):
                            subdir = "github"
                        elif pattern_name in ["npm", "pypi", "docker", "rubygems", "nuget", 
                                            "go_modules", "composer"]:
                            subdir = "pkgs"
                        elif pattern_name == "generic_urls":
                            subdir = "urls"
                        else:
                            subdir = "secrets"
                        # Create subdir and file only if matches exist
                        subdir_path = os.path.join(output_dir, subdir)
                        os.makedirs(subdir_path, exist_ok=True)
                        output_file = os.path.join(subdir_path, f"{pattern_name}.txt")
                        with open(output_file, 'a') as out_file:
                            for match in matches:
                                # Handle single and multi-group matches
                                match_str = match[1] if isinstance(match, tuple) and len(match) > 1 else match[0] if isinstance(match, tuple) else match
                                # Skip if already matched
                                if match_str in matched_urls:
                                    continue
                                # Validate URLs
                                if pattern_name == "generic_urls" and not is_valid_url(match_str):
                                    continue
                                out_file.write(f"{match_str}\n")
                                hist_file.write(f"{repo_name}:{relative_path}:{pattern_name}:{match_str}\n")
                                matched_urls.add(match_str)
            except Exception as e:
                err_file.write(f"Error reading {file_path}: {e}\n")

print("Scanning complete!")
print(f"Results in: {', '.join([os.path.join(output_dir, subdir) for output_dir in output_dirs.values() for subdir in subdirs])}")
print(f"History in: {hist_file_path}")
print(f"Errors in: {errors_file}")
