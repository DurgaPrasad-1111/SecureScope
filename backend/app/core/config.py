from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    app_name: str = 'SecureScope'
    environment: str = 'development'
    debug: bool = False

    database_url: str = 'postgresql+psycopg2://securescope:securescope@db:5432/securescope'

    jwt_secret_key: str = 'change-me'
    jwt_algorithm: str = 'HS256'
    access_token_exp_minutes: int = 20
    refresh_token_exp_minutes: int = 1440

    cors_origins: str = 'http://localhost:5173,http://localhost'
    encryption_key: str = ''

    rate_limit_default: str = '100/minute'
    report_storage_path: str = '/app/reports'

    initial_admin_email: str = ''
    initial_admin_password: str = ''
    initial_admin_name: str = 'Initial Admin'


settings = Settings()
