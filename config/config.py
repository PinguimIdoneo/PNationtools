import os

class Config:
    # Default settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'w5Ib0ARwVLbS0rSwJpzZRA')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Use SQLite as fallback if DATABASE_URL is not set
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://pnationtools_user:cBbTguDKychOxL38ThBPillXNSPUXWHz@dpg-cq27gd56l47c73b124l0-a/pnationtools')

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'postgresql://pnationtools_user:cBbTguDKychOxL38ThBPillXNSPUXWHz@dpg-cq27gd56l47c73b124l0-a/pnationtools'

class ProductionConfig(Config):
    DEBUG = False
    # Ensure the environment variable is set for production database
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

