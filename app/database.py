# database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

# URL de conexión a la base de datos PostgreSQL
# En un entorno de producción, DEBES usar variables de entorno para las credenciales.
# DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:08126172@localhost/BDSOFT")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://ruvay_h3rd_user:U5kCcpRB3I52soG2jwIG0k9km3BhI9L0@dpg-d8q0t6eq1p3s739c0kfg-a.virginia-postgres.render.com/ruvay_h3rd", pool_size=10, max_overflow=20)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Dependencia para obtener una sesión de base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()