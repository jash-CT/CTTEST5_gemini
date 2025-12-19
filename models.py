from datetime import datetime
from enum import Enum

from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, DateTime, Enum as SAEnum, ForeignKey, Text
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class RoleEnum(str, Enum):
    CUSTOMER = "customer"
    OFFICER = "officer"


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(SAEnum(RoleEnum), nullable=False, default=RoleEnum.CUSTOMER)
    created_at = Column(DateTime, default=datetime.utcnow)

    loans = relationship("Loan", back_populates="applicant")

    def is_officer(self):
        return self.role == RoleEnum.OFFICER

    def is_customer(self):
        return self.role == RoleEnum.CUSTOMER


class LoanStatusEnum(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class Loan(db.Model):
    __tablename__ = "loans"

    id = Column(Integer, primary_key=True)
    applicant_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Integer, nullable=False)
    purpose = Column(String(255), nullable=False)
    term_months = Column(Integer, nullable=False)
    status = Column(SAEnum(LoanStatusEnum), default=LoanStatusEnum.PENDING, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    applicant = relationship("User", back_populates="loans")


class AuditActionEnum(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    REVIEW = "review"


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(80), nullable=False)
    resource = Column(String(80), nullable=True)
    resource_id = Column(Integer, nullable=True)
    ip_address = Column(String(100), nullable=True)
    detail = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", foreign_keys=[user_id])
