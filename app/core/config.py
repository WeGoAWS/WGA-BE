# app/core/config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    MONGODB_URI: str = os.getenv("MONGODB_URI", "")
    MONGODB_DB_NAME: str = os.getenv("MONGODB_DB_NAME", "")

    # AWS 설정
    AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")

    # Cognito 설정
    COGNITO_DOMAIN: str = os.getenv("COGNITO_DOMAIN", "")
    COGNITO_CLIENT_ID: str = os.getenv("COGNITO_CLIENT_ID", "")
    COGNITO_IDENTITY_POOL_ID: str = os.getenv("COGNITO_IDENTITY_POOL_ID", "")
    USER_POOL_ID: str = os.getenv("USER_POOL_ID", "")

    # GCP 설정
    GCP_PROJECT_ID: str = os.getenv("GCP_PROJECT_ID", "")
    GCP_CLIENT_ID: str = os.getenv("GCP_CLIENT_ID", "")
    GCP_CLIENT_SECRET: str = os.getenv("GCP_CLIENT_SECRET", "")
    GCP_SERVICE_ACCOUNT_FILE: str = os.getenv("GCP_SERVICE_ACCOUNT_FILE", "")
    GCP_REDIRECT_URI: str = os.getenv("GCP_REDIRECT_URI", "http://localhost:8000/auth/authorize")

    # Azure 설정
    AZURE_TENANT_ID: str = os.getenv("AZURE_TENANT_ID", "")
    AZURE_CLIENT_ID: str = os.getenv("AZURE_CLIENT_ID", "")
    AZURE_CLIENT_SECRET: str = os.getenv("AZURE_CLIENT_SECRET", "")
    AZURE_SUBSCRIPTION_ID: str = os.getenv("AZURE_SUBSCRIPTION_ID", "")
    AZURE_LOG_WORKSPACE_ID: str = os.getenv("AZURE_LOG_WORKSPACE_ID", "")
    AZURE_REDIRECT_URI: str = os.getenv("AZURE_REDIRECT_URI", "http://localhost:8000/auth/authorize")

settings = Settings()
