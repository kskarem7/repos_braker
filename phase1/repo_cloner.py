# بسم الله الرحمن الرحيم
import os
import subprocess
import requests
import sys
import time
import platform
from threading import Thread, Event

# Pre-configured API keys (replace with your keys or leave blank)
api_keys = {
    "github.com": "urkey",
    "gitlab.com": "your_gitlab_api_key_here",
    "bitbucket.org": "your_bitbucket_api_key_here"
}

# Platform config (unchanged from your original)
platforms = {
    "github.com": {"api": "https://api.github.com/orgs/{org}/repos", "clone_prefix": "https://github.com/"},
    "gitlab.com": {"api": "https://gitlab.com/api/v4/groups/{org}/projects", "clone_prefix": "https://gitlab.com/"},
    "bitbucket.org": {"api": "https://api.bitbucket.org/2.0/teams/{org}/repositories", "clone_prefix": "https://bitbucket.org/"}
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
                    if key == '\r':  # Enter key
                        self.toggle_pause()
            else:
                try:
                    rlist, _, _ = self.select.select([sys.stdin], [], [], 0.1)
                    if rlist:
                        input()  # Clear the buffer
                        self.toggle_pause()
                except:
                    pass
            time.sleep(0.1)
    
    def toggle_pause(self):
        if self.pause_event.is_set():
            print("\n[▶] Resuming...")
            self.pause_event.clear()
        else:
            print(f"\n[⏸] Paused on: {self.current_repo}")
            print("[▶] Press Enter to resume | [⏩] Type 's' + Enter to skip")
            self.pause_event.set()
            self.wait_for_skip_or_resume()

    def wait_for_skip_or_resume(self):
        while self.pause_event.is_set() and not self.stop_event.is_set():
            if self.is_windows:
                if self.msvcrt.kbhit():
                    key = self.msvcrt.getch().decode('utf-8', errors='ignore').lower()
                    if key == '\r':
                        print("[▶] Resuming...")
                        self.pause_event.clear()
                    elif key == 's':
                        print(f"[⏩] Skipped: {self.current_repo}")
                        self.stop_event.set()
            else:
                try:
                    rlist, _, _ = self.select.select([sys.stdin], [], [], 0.1)
                    if rlist:
                        user_input = sys.stdin.readline().strip().lower()
                        if user_input == 's':
                            print(f"[⏩] Skipped: {self.current_repo}")
                            self.stop_event.set()
                        else:
                            print("[▶] Resuming...")
                            self.pause_event.clear()
                except:
                    pass

def clone_repos(platform, org, folder_name, api_key=None):
    manager = CloneManager()
    input_thread = Thread(target=manager.check_for_input)
    spinner_thread = Thread(target=manager.spinner)
    
    input_thread.daemon = True
    spinner_thread.daemon = True
    input_thread.start()
    spinner_thread.start()

    try:
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

        response = requests.get(api_url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        repos = response.json()

        if isinstance(repos, dict):
            repos = [repos] if platform == "github.com" else repos.get("projects", repos.get("values", []))

        for repo in repos:
            if manager.stop_event.is_set():
                manager.stop_event.clear()
                continue

            repo_name = repo.get("name")
            manager.current_repo = repo_name
            repo_url = f"{clone_prefix}{org}/{repo_name}.git"
            clone_path = os.path.join(archived_dir if repo.get("archived", False) else public_dir, repo_name)

            # Skip if already cloned (checks folder existence)
            if os.path.exists(clone_path):
                print(f"\r[=] Skipped: {repo_name} (already exists)", " " * 20)
                continue

            try:
                subprocess.run(
                    ["git", "clone", "--quiet", repo_url, clone_path],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print(f"\r[✓] Cloned: {repo_name} ../", " " * 20)
            except subprocess.CalledProcessError:
                print(f"\r[✗] Failed: {repo_name} (retrying...)", " " * 20)
                for _ in range(2):  # 2 retries
                    time.sleep(2)
                    try:
                        subprocess.run(
                            ["git", "clone", "--quiet", repo_url, clone_path],
                            check=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        print(f"\r[✓] Cloned: {repo_name} ../", " " * 20)
                        break
                    except:
                        pass
                else:
                    print(f"\r[✗] Skipped: {repo_name} (too many retries)", " " * 20)

    except Exception as e:
        print(f"\n[!] Critical Error: {e}")
    finally:
        manager.stop_event.set()
        input_thread.join()
        spinner_thread.join()
        print("\n[✔] Cloning completed.")

def main():
    print("Repository Cloner | Press Enter to pause/resume | 's' to skip")
    print("------------------------------------------------------------")
    
    folder_name = input("Folder name (e.g., myNEWtarget): ").strip()
    url = input("URL (e.g., github.com/github): ").strip().replace("https://", "").replace("http://", "").strip("/")

    parts = url.split("/")
    if len(parts) < 2:
        print("[✗] Invalid URL. Use: github.com/orgname")
        return

    platform, org = parts[0], parts[1]
    if platform not in platforms:
        print(f"[✗] Unsupported platform. Use: {list(platforms.keys())}")
        return

    clone_repos(platform, org, folder_name, api_keys.get(platform))

if __name__ == "__main__":
    main()
# الحمد لله رب العالمين
