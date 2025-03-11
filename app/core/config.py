import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    MONGODB_URI: str = os.getenv("MONGODB_URI", "")
    MONGODB_DB_NAME: str = os.getenv("MONGODB_DB_NAME", "")

    AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")

    COGNITO_DOMAIN: str = os.getenv("COGNITO_DOMAIN", "")
    COGNITO_CLIENT_ID: str = os.getenv("COGNITO_CLIENT_ID", "")
    COGNITO_CLIENT_SECRET: str = os.getenv("COGNITO_CLIENT_SECRET", "")
    COGNITO_REDIRECT_URI: str = os.getenv("COGNITO_REDIRECT_URI", "")
    COGNITO_IDENTITY_POOL_ID: str = os.getenv("COGNITO_IDENTITY_POOL_ID", "")
    
    USER_POOL_ID: str = os.getenv("USER_POOL_ID", "")

settings = Settings()
