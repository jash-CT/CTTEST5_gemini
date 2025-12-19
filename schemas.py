from pydantic import BaseModel, Field, EmailStr, conint, constr, ValidationError
from typing import Optional, Literal


class RegisterIn(BaseModel):
    username: constr(min_length=3, max_length=80)
    email: EmailStr
    password: constr(min_length=10, max_length=128)


class LoginIn(BaseModel):
    username: constr(min_length=3, max_length=80)
    password: constr(min_length=10, max_length=128)


class LoanApplyIn(BaseModel):
    amount: conint(gt=0)
    purpose: constr(min_length=3, max_length=255)
    term_months: conint(gt=0, le=360)


class LoanReviewIn(BaseModel):
    decision: Literal["approve", "reject"]
    comment: Optional[constr(max_length=1024)] = None


def validate_request(model_class, data: dict):
    """Validate input JSON with Pydantic and return (obj, None) or (None, error_msg).

    We intentionally return a generic message on validation errors to avoid leaking PII.
    """
    try:
        obj = model_class.parse_obj(data)
        return obj, None
    except ValidationError:
        return None, "Invalid input"
