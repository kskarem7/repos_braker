
#بسم الله الرحمن الرحيم
import os
import subprocess
import requests

# Pre-configured API keys (replace with your keys or leave blank)
api_keys = {
    "github.com": "YOUR_KEY_HERE",
    "gitlab.com": "your_gitlab_api_key_here",
    "bitbucket.org": "your_bitbucket_api_key_here"
}

# Platform config
platforms = {
    "github.com": {"api": "https://api.github.com/orgs/{org}/repos", "clone_prefix": "https://github.com/"},
    "gitlab.com": {"api": "https://gitlab.com/api/v4/groups/{org}/projects", "clone_prefix": "https://gitlab.com/"},
    "bitbucket.org": {"api": "https://api.bitbucket.org/2.0/teams/{org}/repositories", "clone_prefix": "https://bitbucket.org/"}
}

def clone_repos(platform, org, folder_name, api_key=None):
    api_url = platforms[platform]["api"].format(org=org)
    clone_prefix = platforms[platform]["clone_prefix"]
    base_dir = f"{platform}_{folder_name}"
    public_dir = os.path.join(base_dir, f"phase_1-{platform}_repos", "public").replace(":", "-")
    archived_dir = os.path.join(base_dir, f"phase_1-{platform}_repos", "archived").replace(":", "-")

    os.makedirs(public_dir, exist_ok=True)
    os.makedirs(archived_dir, exist_ok=True)

    headers = {"Accept": "application/json"}
    if api_key:
        if platform == "github.com":
            headers["Authorization"] = f"token {api_key}"
        elif platform == "gitlab.com":
            headers["PRIVATE-TOKEN"] = api_key
        elif platform == "bitbucket.org":
            headers["Authorization"] = f"Bearer {api_key}"

    params = {"per_page": 100, "archived": "true"}
    if not api_key and platform in ["github.com", "gitlab.com"]:
        params["visibility"] = "public"

    response = requests.get(api_url, headers=headers, params=params)

    if response.status_code != 200:
        print(f"[!] Error accessing {platform} API: {response.status_code}")
        api_key = input(f"[!] Enter API key for {platform} (or press Enter for public only): ").strip()
        if not api_key:
            api_key = input(f"[!] Enter API key for {platform} (or press Enter for public only): ").strip()
            if api_key:
                headers[platform == "github.com" and "Authorization" or "PRIVATE-TOKEN"] = f"token {api_key}" if platform == "github.com" else api_key
                response = requests.get(api_url, headers=headers, params=params)
        if response.status_code != 200:
            return

    repos = response.json()
    if isinstance(repos, dict):
        if platform == "github.com":
            repos = repos  # GitHub returns a list
        elif platform == "gitlab.com":
            repos = repos.get("projects", [])
        elif platform == "bitbucket.org":
            repos = repos.get("values", [])

    while "next" in response.links:  # Pagination support
        response = requests.get(response.links["next"]["url"], headers=headers, params=params)
        repos.extend(response.json())

    for repo in repos:
        repo_name = repo.get("name")
        repo_url = f"{clone_prefix}{org}/{repo_name}.git"
        clone_path = os.path.join(archived_dir if repo.get("archived", False) else public_dir, repo_name)
        if not os.path.exists(clone_path):
            try:
                subprocess.run(["git", "clone", "--quiet", repo_url, clone_path], check=True)
                print(f"[+] Cloned {repo_name}")
            except subprocess.CalledProcessError:
                print(f"[x] Failed to clone {repo_name}")

def main():
    folder_name = input("Enter folder name (e.g., karim): ").strip()
    url = input("Enter URL (e.g., github.com/orgname): ").strip().replace("https://", "").replace("http://", "").strip("/")

    parts = url.split("/")
    if len(parts) < 2:
        print("[!] Invalid URL format. Use: github.com/orgname")
        return

    platform = parts[0]
    org = parts[1]

    if platform not in platforms:
        print(f"[!] Unsupported platform: {platform}. Supported: {list(platforms.keys())}")
        return

    api_key = api_keys.get(platform)
    clone_repos(platform, org, folder_name, api_key)

if __name__ == "__main__":
    main()
#الحمد لله رب العالمين
