# backend/tancho/pets/models.py

from enum import Enum
from pydantic import BaseModel
from typing import List, Optional

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None

class NewUser(BaseModel):
    username: str
    email: str
    password: str

class UserOnDB(NewUser):
    id_: str
    
class User(BaseModel):
    username: str
    password: str