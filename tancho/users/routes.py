# backend/tancho/pets/routes.py

from bson.objectid import ObjectId
from config.config import DB, CONF
from fastapi import Depends, APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Optional
from passlib.context import CryptContext
import logging
import time
from datetime import timedelta, datetime
from jose import JWTError, jwt

from .models import NewUser, User, UserOnDB, Token, TokenData

SECRET = "THISISMYSECRET!!"
SECRET_KEY = '6defe657c0b49b904b081ba98dc49e5ec7935ce621182928cbbd3bd9db07da7b'
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

passwordContext = CryptContext(schemes = ["bcrypt"], deprecated = "auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

user_router = APIRouter()

def validate_object_id(id_: str):
    try:
        _id = ObjectId(id_)
    except Exception:
        if CONF["fastapi"].get("debug", False):
            logging.warning("Invalid Object ID")
        raise HTTPException(status_code=400)
    return _id

async def _get_pet_or_404(id_: str):
    _id = validate_object_id(id_)
    user = await DB.users.find_one({"_id": _id})
    if user:
        return user
    else:
        raise HTTPException(status_code=404, detail="User not found")

def verify_password(plain_password, hashed_password):
    return passwordContext.verify(plain_password, hashed_password)

def get_password_hash(password):
    return passwordContext.hash(password)

def authenticate_user(username: str, password: str):
    user = DB.users.find({"username": username})
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

def get_user(username: str):
    user = DB.users.find({"username": username})
    if not user:
        return False
    return UserOnDB(**user)

def fix_user_id(user):
    user["id_"] = str(user["_id"])
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@user_router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@user_router.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@user_router.post("/v2/add", response_model=UserOnDB)
async def create_user(user: NewUser):
    hashedPassword = passwordContext.hash(user.password)

    user.password = hashedPassword

    result = await DB.users.insert_one(user.dict())
    if result.inserted_id:
        user = await _get_pet_or_404(result.inserted_id)
        user["id_"] = str(user["_id"])
        return user

@user_router.get("/v2/login")
async def login_user(user: User):
    userResult = DB.users.find({"username": user.username})

    if passwordContext.verify(user.password, userResult["password"]):
        expirationTime = int(time.time() + 3600)
        token = jwt.encode({"exp": expirationTime}, SECRET, algorithm="HS256")

        return {"token": token}
    else:
        return {"Incorrect password!"}

@user_router.get("/login")
async def login(username: str):
    print(username)
    token = 'token'
    return {"token": token}

@user_router.get("/users", response_model=List[UserOnDB])
async def get_users(username: str = None, limit: int = 10, skip: int = 0):
    if username is None:
        userResult = DB.users.find().skip(skip).limit(limit)
    else:
        userResult = DB.users.find({"username": username.value}).skip(skip).limit(limit)
    users = await userResult.to_list(length=limit)
    return list(map(fix_user_id, users))



    userResult = DB.users.find()
    
