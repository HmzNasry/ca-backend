from sqlalchemy import Column, String, Integer, Text, DateTime, Index
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
