from pydantic import BaseModel


class Login(BaseModel):
    username: str
    server_password: str


class SignUp(BaseModel):
    username: str
    display_name: str
    password: str


class SignIn(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class AccountInfo(BaseModel):
    username: str
    display_name: str
    created_at: str | None = None
    last_seen_ip: str | None = None


class UpdateAccount(BaseModel):
    # All optional; provide any subset to update
    username: str | None = None
    display_name: str | None = None
    password: str | None = None
