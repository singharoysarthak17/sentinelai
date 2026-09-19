from pydantic import BaseModel, Field

from rag.retrieve import search
from tools.registry import tool


class SearchPolicyParams(BaseModel):
    query: str = Field(min_length=3, max_length=300)
    role: str = "analyst"  # comes from the analyst's session, never from LLM output
    k: int = Field(default=3, ge=1, le=5)


@tool("search_policy", SearchPolicyParams)
def search_policy(p: SearchPolicyParams):
    return search(p.query, p.role, p.k)