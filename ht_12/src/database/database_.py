from configparser import ConfigParser
from pathlib import Path

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from fastapi import HTTPException, status

config_path = Path(__file__).parent.parent.joinpath('conf/config.ini')

parser = ConfigParser()
parser.read(config_path)

user = parser.get('DB', 'user')
password = parser.get('DB', 'password')
db_name = parser.get('DB', 'db_name')
domain = parser.get('DB', 'domain')
port = parser.get('DB', 'port')

url = f'postgresql://{user}:{password}@{domain}:{port}/{db_name}'

engine = create_engine(url, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    except SQLAlchemyError as error:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    finally:
        db.close()
