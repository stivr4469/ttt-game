import boto3
import os
import json
from dotenv import load_dotenv
from constants import CONTROLS_MAP_FILE

load_dotenv()

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "test")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "test")
AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
LOCALSTACK_ENDPOINT = os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566")

def get_boto3_client(service):
    return boto3.client(
        service,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_DEFAULT_REGION,
        endpoint_url=LOCALSTACK_ENDPOINT
    )

def bucket_exists(s3, name):
    try:
        s3.head_bucket(Bucket=name)
        return True
    except Exception:
        return False

def iam_user_exists(iam, name):
    try:
        iam.get_user(UserName=name)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False
    except Exception:
        return False

def seed_security_groups(ec2):
    """Создаёт Security Groups с намеренно опасными правилами."""
    
    DANGEROUS_SGS = [
        {
            "name": "web-servers-sg",
            "description": "Web servers - intentionally misconfigured",
            "rules": [
                {"port": 22,   "desc": "SSH open to world"},
                {"port": 80,   "desc": "HTTP open to world"},
                {"port": 443,  "desc": "HTTPS open to world"},
            ]
        },
        {
            "name": "database-sg",
            "description": "Database servers - intentionally misconfigured",
            "rules": [
                {"port": 5432, "desc": "PostgreSQL open to world"},
                {"port": 3306, "desc": "MySQL open to world"},
                {"port": 3389, "desc": "RDP open to world"},
            ]
        },
        {
            "name": "admin-access-sg",
            "description": "Admin access - intentionally misconfigured",
            "rules": [
                {"port": 22,   "desc": "SSH open to world"},
                {"port": 3389, "desc": "RDP open to world"},
                {"port": 8080, "desc": "Dev server open to world"},
            ]
        },
    ]
    
    for sg_config in DANGEROUS_SGS:
        name = sg_config["name"]
        
        # Идемпотентность — пропустить если уже существует
        try:
            existing = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": [name]}]
            )["SecurityGroups"]
            if existing:
                print(f"[SKIP] Security Group '{name}' already exists")
                continue
        except Exception:
            pass # Continue to create if not found or error
        
        # Создать SG
        sg = ec2.create_security_group(
            GroupName=name,
            Description=sg_config["description"]
        )
        sg_id = sg["GroupId"]
        
        # Добавить опасные правила (все открыты на 0.0.0.0/0)
        ip_permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": rule["port"],
                "ToPort": rule["port"],
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": rule["desc"]}],
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }
            for rule in sg_config["rules"]
        ]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=ip_permissions
        )
        
        ports = [r["port"] for r in sg_config["rules"]]
        print(f"[SEED] Security Group '{name}' ({sg_id}): ports {ports} open to 0.0.0.0/0")

def seed_dynamodb_tables(dynamodb):
    """Создаёт DynamoDB-таблицы без encryption at rest."""
    
    UNENCRYPTED_TABLES = [
        {
            "name": "users-data",
            "key": "user_id",
            "description": "User PII storage — no encryption"
        },
        {
            "name": "payment-records",
            "key": "transaction_id",
            "description": "Financial records — no encryption"
        },
        {
            "name": "audit-logs",
            "key": "log_id",
            "description": "Audit log table — no encryption"
        },
    ]
    
    existing_tables = dynamodb.list_tables().get("TableNames", [])
    
    for table_config in UNENCRYPTED_TABLES:
        name = table_config["name"]
        key = table_config["key"]
        
        if name in existing_tables:
            print(f"[SKIP] DynamoDB table '{name}' already exists")
            continue
        
        # Создать таблицу БЕЗ SSESpecification (нет шифрования)
        dynamodb.create_table(
            TableName=name,
            KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
            # SSESpecification намеренно отсутствует = нет шифрования
        )
        print(f"[SEED] DynamoDB table '{name}' created WITHOUT encryption (CC6.7 violation)")

def seed_lambda_functions(lambda_client, iam):
    """Создаёт Lambda-функцию с избыточными правами и секретами в открытом виде."""
    
    func_name = "process-payment-data"
    role_name = "lambda-payment-role"
    
    # 1. Создать роль для Lambda (если нет)
    try:
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Action": "sts:AssumeRole", "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}}]
        }
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy)
        )
        # Намеренное нарушение CC6.1: даем слишком широкие права (Full Access)
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess"
        )
        print(f"[SEED] IAM Role '{role_name}' created with S3FullAccess (CC6.1 violation)")
    except Exception:
        pass # Идемпотентность

    # 2. Создать пустую функцию
    try:
        # В LocalStack для создания функции достаточно минимального Zip-архива
        import zipfile
        import io
        import json as json_mod # avoid conflict if any
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
            zip_file.writestr('index.py', 'def handler(event, context): return "ok"')
        
        # Намеренное нарушение CC6.7: секреты в открытых переменных окружения (нет KMS)
        lambda_client.create_function(
            FunctionName=func_name,
            Runtime="python3.9",
            Role=f"arn:aws:iam:us-east-1:000000000000:role/{role_name}",
            Handler="index.handler",
            Code={"ZipFile": zip_buffer.getvalue()},
            Environment={
                "Variables": {
                    "STRIPE_API_KEY": "sk_test_EXAMPLE_DO_NOT_USE_IN_PROD", # В ОТКРЫТОМ ВИДЕ!
                    "DB_PASSWORD": "super-secret-password-123"
                }
            }
        )
        print(f"[SEED] Lambda '{func_name}' created with raw secrets in EnvVars (CC6.7 violation)")
    except Exception as e:
        if "ResourceConflictException" not in str(e):
            print(f"Error seeding Lambda: {e}")

def main():
    s3 = get_boto3_client("s3")
    iam = get_boto3_client("iam")
    ec2 = get_boto3_client("ec2")
    dynamodb = get_boto3_client("dynamodb")
    lambda_client = get_boto3_client("lambda")

    # S3 Resources
    print("Creating S3 resources...")
    v_bucket = "vulnerable-public-bucket"
    if not bucket_exists(s3, v_bucket):
        s3.create_bucket(Bucket=v_bucket)
        s3.put_bucket_acl(Bucket=v_bucket, ACL="public-read")
        print(f"[SEED] S3: {v_bucket} (PUBLIC — нарушение CC6.1/CC6.3/CC6.7)")
    else:
        print(f"[SEED] S3: {v_bucket} уже существует — пропуск")

    s_bucket = "safe-private-bucket"
    if not bucket_exists(s3, s_bucket):
        s3.create_bucket(Bucket=s_bucket)
        print(f"[SEED] S3: {s_bucket} (PRIVATE — норма)")
    else:
        print(f"[SEED] S3: {s_bucket} уже существует — пропуск")

    # IAM Resources
    print("Creating IAM resources...")
    admin_user = "insecure-admin"
    if not iam_user_exists(iam, admin_user):
        iam.create_user(UserName=admin_user)
        iam.attach_user_policy(
            UserName=admin_user,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )
        print(f"[SEED] IAM: {admin_user} (AdministratorAccess, no MFA, no tags — нарушение CC6.1/CC6.2/CC6.3)")
    else:
        print(f"[SEED] IAM: {admin_user} уже существует — пропуск")

    readonly_user = "secure-readonly"
    if not iam_user_exists(iam, readonly_user):
        iam.create_user(
            UserName=readonly_user,
            Tags=[{'Key': 'approved', 'Value': 'true'}]
        )
        iam.attach_user_policy(
            UserName=readonly_user,
            PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess"
        )
        print(f"[SEED] IAM: {readonly_user} (ReadOnlyAccess, approved=true — норма)")
    else:
        print(f"[SEED] IAM: {readonly_user} уже существует — пропуск")

    print("\n--- Seeding EC2 Security Groups (CC6.6) ---")
    seed_security_groups(ec2)

    print("\n--- Seeding DynamoDB Tables without encryption (CC6.7) ---")
    seed_dynamodb_tables(dynamodb)

    print("\n--- Seeding AWS Lambda Functions (CC6.1, CC6.7) ---")
    seed_lambda_functions(lambda_client, iam)

    print("\n[SEED] CloudTrail: не настроен (нарушение CC7.1/CC7.2)")
    print("[SEED] Seeding complete.")

if __name__ == "__main__":
    main()
