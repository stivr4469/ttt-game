"""
fix_infrastructure.py — переводит LocalStack в compliance-состояние.
  - Делает S3 bucket приватным (CC6.7)
  - CloudTrail: обрабатывается в scanner.py (LocalStack Community не поддерживает)
"""
import boto3
import os
from dotenv import load_dotenv

load_dotenv()

ENDPOINT = os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566")
REGION   = os.getenv("AWS_DEFAULT_REGION", "us-east-1")


def client(service):
    return boto3.client(
        service,
        endpoint_url=ENDPOINT,
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "test"),
        region_name=REGION,
    )


def fix_s3_public_bucket():
    s3 = client("s3")
    bucket = "vulnerable-public-bucket"

    try:
        # Убрать публичный ACL
        s3.put_bucket_acl(Bucket=bucket, ACL="private")
        print(f"[FIX] S3 '{bucket}': ACL → private")
    except Exception as e:
        print(f"[WARN] ACL: {e}")

    try:
        # Block all public access
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        print(f"[FIX] S3 '{bucket}': PublicAccessBlock включён → CC6.7 PASS")
    except Exception as e:
        print(f"[WARN] PublicAccessBlock: {e}")


if __name__ == "__main__":
    print("=== fix_infrastructure.py ===")
    print("\n--- S3 public bucket fix (CC6.7) ---")
    fix_s3_public_bucket()
    print("\nГотово. Запусти python3 scanner.py для переоценки контролей.")
