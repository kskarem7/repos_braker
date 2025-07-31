# بسم الله الرحمن الرحيم
import os
import subprocess
import requests
import sys
import time
import platform
import argparse
from threading import Thread, Event

# Pre-configured API keys (replace with your keys)
api_keys = {
    "github.com": "your_github_api_key_here",
    "gitlab.com": "your_gitlab_api_key_here",
    "bitbucket.org": "your_bitbucket_api_key_here"
}

# Platform configurations
platforms = {
    "github.com": {
        "api": "https://api.github.com/orgs/{org}/repos",
        "clone_prefix": "https://github.com/",
        "fork_key": "fork"
    },
    "gitlab.com": {
        "api": "https://gitlab.com/api/v4/groups/{org}/projects",
        "clone_prefix": "https://gitlab.com/",
        "fork_key": "forked_from_project"
    },
    "bitbucket.org": {
        "api": "https://api.bitbucket.org/2.0/teams/{org}/repositories",
        "clone_prefix": "https://bitbucket.org/",
        "fork_key": "parent"
    }
}

class CloneManager:
    def __init__(self):
        self.pause_event = Event()
        self.stop_event = Event()
        self.current_repo = ""
        self.spinner_chars = ['..', '\\', '|', '/']
        self.spinner_pos = 0
        self.is_windows = sys.platform == "win32"
        
        if self.is_windows:
            import msvcrt
            self.msvcrt = msvcrt
        else:
            import select
            self.select = select

    def clear_line(self):
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    def spinner(self):
        while not self.stop_event.is_set():
            if not self.pause_event.is_set():
                sys.stdout.write(f"\r[+] Cloning {self.current_repo} {self.spinner_chars[self.spinner_pos]}")
                sys.stdout.flush()
                self.spinner_pos = (self.spinner_pos + 1) % len(self.spinner_chars)
            time.sleep(0.1)

    def check_for_input(self):
        while not self.stop_event.is_set():
            if self.is_windows:
                if self.msvcrt.kbhit():
                    key = self.msvcrt.getch().decode('utf-8', errors='ignore')
                    if key == '\r':
                        self.toggle_pause()
            else:
                try:
                    rlist, _, _ = self.select.select([sys.stdin], [], [], 0.1)
                    if rlist:
                        input()
                        self.toggle_pause()
                except:
                    pass
            time.sleep(0.1)

    def toggle_pause(self):
        if self.pause_event.is_set():
            self.clear_line()
            print("\n\033[92m[▶]\033[0m Resuming...")
            self.pause_event.clear()
        else:
            self.clear_line()
            print(f"\n\033[93m[⏸]\033[0m \033[1mPAUSED on:\033[0m {self.current_repo}")
            print("\033[91m[⏩] PRESS: Enter=Resume | 's'+Enter=Skip\033[0m")
            self.pause_event.set()
            time.sleep(1)
            self.wait_for_skip_or_resume()

    def wait_for_skip_or_resume(self):
        while self.pause_event.is_set():
            if self.is_windows:
                if self.msvcrt.kbhit():
                    key = self.msvcrt.getch().decode().lower()
                    if key == '\r':
                        self.clear_line()
                        print("\033[92m[▶] Resuming...\033[0m")
                        self.pause_event.clear()
                    elif key == 's':
                        self.clear_line()
                        print(f"\033[91m[⏩] SKIPPED: {self.current_repo}\033[0m")
                        self.stop_event.set()
            else:
                try:
                    if self.select.select([sys.stdin], [], [], 0.1)[0]:
                        cmd = sys.stdin.readline().strip().lower()
                        if cmd == 's':
                            self.clear_line()
                            print(f"\033[91m[⏩] SKIPPED: {self.current_repo}\033[0m")
                            self.stop_event.set()
                        else:
                            self.clear_line()
                            print("\033[92m[▶] Resuming...\033[0m")
                            self.pause_event.clear()
                except:
                    pass
            time.sleep(0.1)

def clone_repos(platform, org, folder_name, api_key=None, scan_forks=False):
    manager = CloneManager()
    input_thread = Thread(target=manager.check_for_input)
    spinner_thread = Thread(target=manager.spinner)
    
    input_thread.daemon = True
    spinner_thread.daemon = True
    input_thread.start()
    spinner_thread.start()

    try:
        platform_config = platforms[platform]
        api_url = platform_config["api"].format(org=org)
        headers = {"Accept": "application/json"}
        
        if api_key:
            if platform == "github.com":
                headers["Authorization"] = f"token {api_key}"
            elif platform == "gitlab.com":
                headers["PRIVATE-TOKEN"] = api_key
            elif platform == "bitbucket.org":
                headers["Authorization"] = f"Bearer {api_key}"

        params = {"per_page": 100}
        if not api_key and platform in ["github.com", "gitlab.com"]:
            params["visibility"] = "public"

        response = requests.get(api_url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        repos = response.json()

        if isinstance(repos, dict):
            repos = [repos] if platform == "github.com" else repos.get("projects", repos.get("values", []))

        base_dir = f"{platform}_{folder_name}"
        public_dir = os.path.join(base_dir, f"phase_1-{platform}_repos", "public")
        archived_dir = os.path.join(base_dir, f"phase_1-{platform}_repos", "archived")

        os.makedirs(public_dir, exist_ok=True)
        os.makedirs(archived_dir, exist_ok=True)

        for repo in repos:
            if manager.stop_event.is_set():
                manager.stop_event.clear()
                continue

            repo_name = repo.get("name")
            manager.current_repo = repo_name

            # Skip forks unless explicitly requested
            if not scan_forks and repo.get(platform_config["fork_key"]):
                manager.clear_line()
                print(f"\r[=] Skipped: {repo_name} (forked repo)", " " * 20)
                continue

            repo_url = f"{platform_config['clone_prefix']}{org}/{repo_name}.git"
            clone_path = os.path.join(archived_dir if repo.get("archived", False) else public_dir, repo_name)

            if os.path.exists(clone_path):
                manager.clear_line()
                print(f"\r[=] Skipped: {repo_name} (exists)", " " * 20)
                continue

            try:
                subprocess.run(
                    ["git", "clone", "--quiet", repo_url, clone_path],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                manager.clear_line()
                print(f"\r[✓] Cloned: {repo_name} ../", " " * 20)
            except subprocess.CalledProcessError:
                manager.clear_line()
                print(f"\r[✗] Failed: {repo_name} (retrying...)", " " * 20)
                for _ in range(2):
                    time.sleep(2)
                    try:
                        subprocess.run(
                            ["git", "clone", "--quiet", repo_url, clone_path],
                            check=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        manager.clear_line()
                        print(f"\r[✓] Cloned: {repo_name} ../", " " * 20)
                        break
                    except:
                        pass
                else:
                    manager.clear_line()
                    print(f"\r[✗] Skipped: {repo_name} (max retries)", " " * 20)

    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
    finally:
        manager.stop_event.set()
        input_thread.join()
        spinner_thread.join()
        print("\n[✔] Scan completed")

def main():
    parser = argparse.ArgumentParser(description="Advanced Repository Cloner")
    parser.add_argument("url", help="Organization URL (e.g. github.com/sophos)")
    parser.add_argument("--scan-forks", action="store_true", help="Include forked repositories")
    args = parser.parse_args()

    url = args.url.strip().lower().replace("https://", "").replace("http://", "").strip("/")
    parts = url.split("/")
    
    if len(parts) < 2:
        print("[✗] Invalid URL format. Use: github.com/orgname")
        return

    platform, org = parts[0], parts[1]
    if platform not in platforms:
        print(f"[✗] Unsupported platform. Choose from: {list(platforms.keys())}")
        return

    folder_name = input("Output folder name (e.g., sophos_scan): ").strip()
    clone_repos(platform, org, folder_name, api_keys.get(platform), args.scan_forks)

if __name__ == "__main__":
    main()
# الحمد لله رب العالمين
