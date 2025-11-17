from datetime import datetime, timezone
from fastapi import HTTPException

from sqlalchemy.ext.asyncio.session import AsyncSession
from sqlalchemy import select

from database import UserModel, ActivationTokenModel
from schemas import UserRegistrationRequestSchema
from security.passwords import hash_password
import secrets
from sqlalchemy.orm import joinedload



async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    db_user = UserModel.create(
        email=user.email,
        raw_password=user.password,
        group_id=1,
    )
    db.add(db_user)
    await db.flush()
    activation_token = ActivationTokenModel(user_id=db_user.id)
    db.add(activation_token)

    await db.commit()
    await db.refresh(db_user)
    return db_user

async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


async def activate_user(db: AsyncSession, email: str, token: str):

    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == email)
    )
    user = result.unique().scalar_one_or_none()

    if not user:
        raise HTTPException(404, "User not found.")

    if user.is_active:
        raise HTTPException(400, "User account is already active.")

    if not user.activation_token:
        raise HTTPException(400, "No activation token found.")  # ✓

    token = token.strip()

    if user.activation_token.token != token:
        raise HTTPException(400, "Invalid activation token.")  # ✓

    if user.activation_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(400, "Activation token has expired.")  # ✓

    user.is_active = True

    await db.delete(user.activation_token)

    await db.commit()
    await db.refresh(user)

    return user