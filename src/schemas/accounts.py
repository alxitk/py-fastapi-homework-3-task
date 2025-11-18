import re

from pydantic import BaseModel, EmailStr, field_validator, Field


class UserRegistrationRequestSchema(BaseModel):
    """Схема для регистрации пользователя"""
    email: EmailStr
    password: str = Field(...)

    @field_validator("password")
    @classmethod
    def validate_strong_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not re.search(r'[A-Z]', value):
            raise ValueError('Password must contain at least one uppercase letter.')
        if not re.search(r'[a-z]', value):
            raise ValueError('Password must contain at least one lower letter.')
        if not re.search(r'\d', value):
            raise ValueError('Password must contain at least one digit.')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise ValueError('Password must contain at least one special character: @, $, !, %, *, ?, #, &.')
        return value


class UserRegistrationResponseSchema(BaseModel):
    """Схема ответа после регистрации"""
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    """Схема для активации аккаунта"""
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    """Общая схема для ответов с сообщением"""
    message: str


class PasswordResetRequestSchema(BaseModel):
    """Схема для завершения сброса пароля (используется в /reset-password/complete/)"""
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_strong_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not re.search(r'[A-Z]', value):
            raise ValueError('Password must contain at least one uppercase letter.')
        if not re.search(r'[a-z]', value):
            raise ValueError('Password must contain at least one lower letter.')
        if not re.search(r'\d', value):
            raise ValueError('Password must contain at least one digit.')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise ValueError('Password must contain at least one special character: @, $, !, %, *, ?, #, &.')
        return value


class PasswordResetCompleteRequestSchema(BaseModel):
    """Схема для запроса токена сброса пароля (используется в /password-reset/request/)"""
    email: EmailStr


class UserLoginRequestSchema(BaseModel):
    """Схема для входа пользователя"""
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    """Схема ответа после входа"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    """Схема для обновления access token"""
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    """Схема ответа с новым access token"""
    access_token: str
    token_type: str = "bearer"