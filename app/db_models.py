from sqlalchemy import Column, String, Integer, Text, DateTime, Index, Boolean, JSON
from .db import Base
from datetime import datetime


class Message(Base):
    __tablename__ = "messages"
    id = Column(String(128), primary_key=True)
    thread = Column(String(8), index=True)  # 'main' | 'dm' | 'gc'
    sender = Column(String(64), index=True)
    scope = Column(String(128), index=True, nullable=True)  # DM id or GC id; null for main
    type = Column(String(16), index=True)  # 'message' | 'media' | 'system'
    text = Column(Text, nullable=True)
    url = Column(Text, nullable=True)
    mime = Column(String(128), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index("ix_messages_thread_scope_ts", "thread", "scope", "timestamp"),
    )


class GroupChat(Base):
    __tablename__ = "group_chats"
    id = Column(String(128), primary_key=True)
    name = Column(String(120), nullable=False)
    creator = Column(String(64), index=True, nullable=True)


class GroupMember(Base):
    __tablename__ = "group_members"
    id = Column(Integer, primary_key=True, autoincrement=True)
    gcid = Column(String(128), index=True)
    user = Column(String(64), index=True)
    __table_args__ = (
        Index("ix_group_members_unique", "gcid", "user", unique=True),
    )


class AccountUser(Base):
    __tablename__ = "accounts"
    id = Column(String(64), primary_key=True)
    username = Column(String(120), nullable=False)
    username_key = Column(String(120), nullable=False, unique=True, index=True)
    display_name = Column(String(120), nullable=False, default="")
    pass_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen_ip = Column(String(64), nullable=True)


class UserRegistry(Base):
    __tablename__ = "user_registry"
    id = Column(String(64), primary_key=True)
    username = Column(String(120), unique=True, index=True, nullable=True)
    ips = Column(JSON, default=list, nullable=False)
    tag_text = Column(String(120), nullable=True)
    tag_color = Column(String(32), nullable=True)
    tag_locked = Column(Boolean, default=False, nullable=False)


class BannedUser(Base):
    __tablename__ = "banned_users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(120), unique=True, nullable=False)
    last_ip = Column(String(64), nullable=True)


class BannedIP(Base):
    __tablename__ = "banned_ips"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(64), unique=True, nullable=False)


class AdminAllowUser(Base):
    __tablename__ = "admin_allow_users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(120), unique=True, nullable=False)
    last_ip = Column(String(64), nullable=True)


class AdminAllowIP(Base):
    __tablename__ = "admin_allow_ips"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(64), unique=True, nullable=False)


class AdminBlacklistUser(Base):
    __tablename__ = "admin_blacklist_users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(120), unique=True, nullable=False)
    last_ip = Column(String(64), nullable=True)


class AdminBlacklistIP(Base):
    __tablename__ = "admin_blacklist_ips"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(64), unique=True, nullable=False)
