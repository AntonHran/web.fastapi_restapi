from fastapi import Depends, HTTPException, status, APIRouter, Security
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2PasswordRequestForm,
)
from sqlalchemy.orm import Session

from ht_12.src.database.database_ import get_db
from ht_12.src.repository import users as repository_users
from ht_12.src.schemes.users import UserModel, UserResponse, TokenModel
from ht_12.src.services.auth import auth_token, auth_password


router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer()


@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def signup(body: UserModel, db: Session = Depends(get_db)):
    exist_user = await repository_users.get_user_by_email(body.email, db)
    if exist_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")
    body.password = auth_password.get_password_hash(body.password)
    new_user = await repository_users.create_user(body, db)
    return new_user


@router.post("/login", response_model=TokenModel)
async def login(body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = await repository_users.get_user_by_email(body.username, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email")
    if not auth_password.verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
    # generate JWT
    access_token = await auth_token.create_access_token(data={"sub": user.email})
    refresh_token_ = await auth_token.create_refresh_token(data={"sub": user.email})
    await repository_users.update_token(user, refresh_token_, db)
    return {"access_token": access_token, "refresh_token": refresh_token_, "token_type": "bearer"}


@router.get("/refresh_token", response_model=TokenModel)
async def refresh_token(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    email = await auth_token.decode_refresh_token(token)
    user = await repository_users.get_user_by_email(email, db)
    if user.refresh_token != token:
        await repository_users.update_token(user, None, db)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    access_token = await auth_token.create_access_token(data={"sub": email})
    refresh_token_ = await auth_token.create_refresh_token(data={"sub": user.email})
    await repository_users.update_token(user, refresh_token_, db)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token_,
        "token_type": "bearer",
    }
