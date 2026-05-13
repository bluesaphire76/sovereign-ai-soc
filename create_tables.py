from database import engine
from models import Base

print("Creating tables...")

Base.metadata.create_all(bind=engine)

print("Done.")

