from datetime import datetime, timezone
from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud.user import get_user_by_email, create_user, activate_user
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, UserActivationRequestSchema, \
    MessageResponseSchema
from security.interfaces import JWTAuthManagerInterface
from fastapi.security import OAuth2PasswordBearer

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@router.post("/register/", response_model=UserRegistrationResponseSchema)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {db_user.email} already exists.")
    return await create_user(db, user)


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_account(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    """
    Activate user account with email and activation token.

    Request:
    {
        "email": "test@example.com",
        "token": "generated_token_here"
    }

    Response (200):
    {
        "message": "User account activated successfully."
    }
    """
    await activate_user(db, data.email, data.token)

    return {
        "message": "User account activated successfully.",
        "success": True
            }