"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogpost" collection
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional

class AuthUser(BaseModel):
    """
    Authentication users collection schema
    Collection name: "authuser" (lowercase of class name)
    """
    name: Optional[str] = Field(None, description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    avatar_url: Optional[str] = Field(None, description="Optional profile avatar URL")
    is_active: bool = Field(True, description="Whether user is active")

class BlogPost(BaseModel):
    """
    Example blog post schema (not yet used by API)
    Collection name: "blogpost"
    """
    title: str
    slug: str
    excerpt: Optional[str] = None
    content: str
    author_id: Optional[str] = None
    cover_image: Optional[str] = None
    tags: list[str] = []
    published: bool = True
