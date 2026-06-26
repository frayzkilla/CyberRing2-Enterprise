#!/usr/bin/env python3
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / '.env')

try:
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
except ImportError:
    print('[!] psycopg2 is not installed, skipping database bootstrap')
    sys.exit(0)



def create_database():
    time.sleep(2)

    connection_params = {
        'host': os.getenv('DB_HOST', 'postgres'),
        'port': int(os.getenv('DB_PORT', '5432')),
        'user': os.getenv('DB_USER', 'postgres'),
        'password': os.getenv('DB_PASSWORD', 'postgres'),
        'database': 'postgres',
    }

    try:
        connection = psycopg2.connect(**connection_params)
        connection.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = connection.cursor()

        cursor.execute("SELECT 1 FROM pg_database WHERE datname = 'cybernet'")
        exists = cursor.fetchone()

        if not exists:
            print('[*] Creating database cybernet...')
            cursor.execute('CREATE DATABASE cybernet')
            print('[✓] Database cybernet created')
        else:
            print('[✓] Database cybernet already exists')

        cursor.close()
        connection.close()
        return True
    except Exception as exc:
        print(f'[!] Database bootstrap failed: {exc}')
        return False


if __name__ == '__main__':
    create_database()
    print('[*] Continuing application startup...')
