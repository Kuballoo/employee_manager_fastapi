from sqlalchemy.orm import sessionmaker

from models import engine

# Create a configured "Session" class
SessionLocal = sessionmaker(autocommit=False, bind=engine)

def get_db():
    """Yield a database session and ensure it is closed after use."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()