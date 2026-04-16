import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    PDNS_API_URL = os.getenv("PDNS_API_URL", "http://127.0.0.1:8081")
    PDNS_API_KEY = os.getenv("PDNS_API_KEY", "")
