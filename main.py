from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from contacts import models, schemas, database
from typing import List
from datetime import date, timedelta
from sqlalchemy import func
from passlib.context import CryptContext
from service_auth import create_access_token, create_refresh_token, authenticate_user, get_current_user

app = FastAPI(
    title="Contacts API",
    description="API for managing contacts.",
    version="1.1.0",
)
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

@app.post("/users/", response_model=schemas.UserResponse, status_code=201)
async def create_user(user: models.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail=".Username already registered")
    hashed_password = get_password_hash(user.password)
    new_user = models.User(username=user.username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.get("/contacts/birthdays/next_week")
async def get_birthdays_next_week(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    today = date.today()

    next_week = today + timedelta(days=7)

    contacts = (
        db.query(models.Contact)
        .filter(
            (func.extract("month", models.Contact.birth_date) == today.month)
            & (func.extract("day", models.Contact.birth_date) >= today.day)
            & (func.extract("day", models.Contact.birth_date) <= next_week.day)
        )
        .all()
    )

    return contacts


@app.get("/contacts/search", response_model=List[schemas.Contact])
def search_contacts(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
    name: str = Query(None, description="Ім'я контакту для пошуку"),
    last_name: str = Query(None, description="Прізвище контакту для пошуку"),
    email: str = Query(None, description="Електронна адреса контакту для пошуку"),
):
    query = db.query(models.Contact).filter(models.Contact.user_id == current_user.id)

    if name:
        query = query.filter(models.Contact.first_name.contains(name))

    if last_name:
        query = query.filter(models.Contact.last_name.contains(last_name))

    if email:
        query = query.filter(models.Contact.email.contains(email))

    contacts = query.all()

    return contacts


@app.post("/contacts/", response_model=schemas.Contact)
def create_contact(contact: schemas.ContactCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    db_contact = models.Contact(**contact.dict(), user_id=current_user.id)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact



@app.get("/contacts/{contact_id}", response_model=schemas.Contact)
def read_contact(
    contact_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)
):
    db_contact = (
        db.query(models.Contact)
        .filter(models.Contact.id == contact_id, models.Contact.user_id == current_user.id)
        .first()
    )
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return db_contact


@app.get("/contacts/", response_model=list[schemas.Contact])
def read_contacts(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    contacts = (
        db.query(models.Contact)
        .filter(models.Contact.user_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    return contacts


@app.put("/contacts/{contact_id}", response_model=schemas.Contact)
def update_contact(
    contact_id: int,
    contact: schemas.ContactUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    db_contact = (
        db.query(models.Contact)
        .filter(models.Contact.id == contact_id, models.Contact.user_id == current_user.id)
        .first()
    )
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")

    for key, value in contact.dict().items():
        setattr(db_contact, key, value)

    db.commit()
    db.refresh(db_contact)
    return db_contact


@app.delete("/contacts/{contact_id}", response_model=schemas.Contact)
def delete_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    db_contact = (
        db.query(models.Contact)
        .filter(models.Contact.id == contact_id, models.Contact.user_id == current_user.id)
        .first()
    )
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    db.delete(db_contact)
    db.commit()
    return db_contact


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
