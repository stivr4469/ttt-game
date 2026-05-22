import os
from dotenv import load_dotenv

load_dotenv()

GITHUB_REPO = os.getenv("GITHUB_REPO")

def main():
    if not GITHUB_REPO:
        print("[ERROR] GITHUB_REPO not set in .env")
        return

    print(f"[SEED] GitHub repo: {GITHUB_REPO}")
    print(f"[SEED] Branch protection: NOT configured (CC8.1 violation expected)")
    print(f"[SEED] Recent commits to main: will be scanned for direct pushes (CC3.4)")
    print("[SEED] GitHub seeding complete (minimal setup, violations already exist).")

if __name__ == "__main__":
    main()
