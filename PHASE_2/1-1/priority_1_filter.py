import os
import re
import shutil

# Private filters for priority files
private_filters = {
    'p1_1': re.compile(r'^(\.github/workflows/.*\.ya?ml|\.gitlab-ci\.ya?ml|\.travis\.ya?ml|bitbucket-pipelines\.ya?ml|buildspec\.ya?ml|\.circleci/config\.ya?ml|Jenkinsfile|azure-pipelines\.ya?ml)$'),
    'p1_2': re.compile(r'.*(gitlab|travis|bitbucket|circleci|jenkins|azure|workflow|pipeline|ci|cd|deploy|build).*\.(ya?ml|json)$'),
    'p1_3': re.compile(r'.*\.(yml|yaml|sh)$')
}

# Public regex patterns
public_patterns = {
    'urls': re.compile(r'https?://\S+'),  # Any URL
    'github': re.compile(r'github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-]+[^/\s]*'),  # GitHub repos
    'github_io': re.compile(r'https?://[a-zA-Z0-9-]+\.github\.io(?:/[^\s]*)?')  # GitHub.io with optional path
}

# Get user input for folder name
base_dir = input("Enter folder name (e.g., github.com_projectrepo): ").strip()
public_dir = os.path.join(base_dir, 'phase_1-github.com_repos', 'public')
priority_dir = os.path.join(base_dir, 'priority_1', 'p1_repos')
output_dirs = {
    'p1_1': os.path.join(base_dir, 'priority_1', 'p1_1_exact_filenames'),
    'p1_2': os.path.join(base_dir, 'priority_1', 'p1_2_general_filenames'),
    'p1_3': os.path.join(base_dir, 'priority_1', 'p1_3_yml_sh_yaml')
}

# Ensure output directories exist
for dir_path in [priority_dir] + list(output_dirs.values()):
    os.makedirs(dir_path, exist_ok=True)

# Step 1: Scan public/ for priority files and track repo names
public_files = []
repo_file_map = {}
for root, _, files in os.walk(public_dir):
    repo_name = os.path.basename(root) if root != public_dir else 'default_repo'
    for file in files:
        file_path = os.path.join(root, file)
        relative_path = os.path.relpath(file_path, public_dir)
        for pattern in private_filters.values():
            if pattern.search(relative_path):
                public_files.append(file_path)
                repo_file_map[file_path] = repo_name
                break

# Step 2: Decide whether to move files
new_files_moved = False
default_repo_dir = os.path.join(priority_dir, 'default_repo')
os.makedirs(default_repo_dir, exist_ok=True)

# Check if p1_repos exists and has files
p1_files = []
for root, _, files in os.walk(priority_dir):
    for file in files:
        p1_files.append(file)

if os.path.exists(priority_dir) and p1_files and public_files:
    # Prompt only if p1_repos has files and public has more to move
    choice = input(f"Found {len(public_files)} priority files in public/. Rescan and move (m) or skip to regex (r)? ").lower()
    if choice == 'm':
        new_files_moved = True
        # Clear output files and historical.txt
        for output_dir in output_dirs.values():
            for file in ['urls.txt', 'github.txt', 'github_io.txt']:
                file_path = os.path.join(output_dir, file)
                if os.path.exists(file_path):
                    open(file_path, 'w').close()  # Clear file
        hist_file_path = os.path.join(base_dir, 'historical.txt')
        if os.path.exists(hist_file_path):
            open(hist_file_path, 'w').close()  # Clear historical
else:
    new_files_moved = True  # No p1_repos or empty, move files
    # Clear output files and historical.txt
    for output_dir in output_dirs.values():
        for file in ['urls.txt', 'github.txt', 'github_io.txt']:
            file_path = os.path.join(output_dir, file)
            if os.path.exists(file_path):
                open(file_path, 'w').close()  # Clear file
    hist_file_path = os.path.join(base_dir, 'historical.txt')
    if os.path.exists(hist_file_path):
        open(hist_file_path, 'w').close()  # Clear historical

# Step 3: Move priority files if needed
if new_files_moved:
    for file_path in public_files:
        shutil.move(file_path, os.path.join(default_repo_dir, os.path.basename(file_path)))

# Step 4: Scan moved files for patterns
with open(os.path.join(base_dir, 'historical.txt'), 'a') as hist_file:
    for root, _, files in os.walk(priority_dir):
        for file in files:
            file_path = os.path.join(root, file)
            # Find the original repo name for this file
            repo_name = next((repo for path, repo in repo_file_map.items() if os.path.basename(path) == file), 'default_repo')
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Determine filter type
                    filter_type = None
                    relative_path = os.path.relpath(file_path, priority_dir)
                    for filter_name, pattern in private_filters.items():
                        if pattern.search(os.path.join('default_repo', relative_path)):
                            filter_type = filter_name
                            break
                    if not filter_type:
                        continue

                    # Apply public regex
                    output_dir = output_dirs[filter_type]
                    for category, pattern in public_patterns.items():
                        matches = pattern.findall(content)
                        if matches:
                            with open(os.path.join(output_dir, f'{category}.txt'), 'a') as out_file:
                                for match in matches:
                                    out_file.write(f'{match}\n')  # Clean output
                                    hist_file.write(f'{repo_name}:{file}:{match}\n')  # Historical log with true repo
            except Exception as e:
                print(f"Error reading {file_path}: {e}")

print("Scanning complete. Check 'priority_1' inside your folder for results and 'historical.txt' for logs.")
