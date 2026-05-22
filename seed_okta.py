import os
from dotenv import load_dotenv
from okta_client import OktaClient
import logging

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

OKTA_DOMAIN = os.getenv("OKTA_DOMAIN")
OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN")

TEST_USERS = [
    {
        "firstName": "NoMFA",
        "lastName": "TestUser",
        "email": "test.nomfa@marineso.com",
        "login": "test.nomfa@marineso.com",
        # Нарушение CC6.1: пользователь активен, MFA не назначен
    },
    {
        "firstName": "Safe",
        "lastName": "TestUser",
        "email": "test.safe@marineso.com",
        "login": "test.safe@marineso.com",
        # Норма: обычный пользователь без привилегий
    }
]

def main():
    if not OKTA_DOMAIN or not OKTA_API_TOKEN:
        logger.error("OKTA_DOMAIN or OKTA_API_TOKEN not set in environment.")
        return

    with OktaClient(OKTA_DOMAIN, OKTA_API_TOKEN) as client:
        print("Fetching existing Okta users...")
        # Note: list_users filters by ACTIVE. We might need to check all users to avoid login conflicts.
        # But for seeding, we'll try to find if they exist.
        try:
            existing_users = client._get_all("/users")
        except Exception as e:
            logger.error(f"Failed to fetch users: {e}")
            return

        existing_logins = {user["profile"]["login"] for user in existing_users}

        for user_data in TEST_USERS:
            login = user_data["login"]
            if login in existing_logins:
                print(f"Okta user {login} already exists. Skipping.")
                continue
                
            print(f"Creating Okta user: {login}...")
            try:
                client.create_user(user_data, activate=False)
                print(f"[SEED] Created Okta user: {login} ({'no MFA — violation CC6.1' if 'nomfa' in login else 'normal user'})")
            except Exception as e:
                logger.error(f"Failed to create user {login}: {e}")

    print("[SEED] Okta seeding complete.")

if __name__ == "__main__":
    main()
