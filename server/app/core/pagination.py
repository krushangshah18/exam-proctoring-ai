from typing import Generic, TypeVar, Sequence, Dict, Any
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Query
import math

T = TypeVar("T")

class PaginatedResponse(BaseModel, Generic[T]):
    items: Sequence[T]
    total: int
    page: int
    size: int
    pages: int

    model_config = ConfigDict(from_attributes=True)

def paginate(query: Query, page: int = 1, size: int = 10) -> Dict[str, Any]:
    """
    Standardizes database querying into a paginated dictionary structure.
    """
    page = max(1, page)
    size = max(1, size)
    
    total = query.count()
    pages = math.ceil(total / size) if size > 0 else 0
    items = query.offset((page - 1) * size).limit(size).all()
    
    return {
        "items": items,
        "total": total,
        "page": page,
        "size": size,
        "pages": pages
    }
