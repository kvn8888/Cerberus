from enum import Enum

from pydantic import BaseModel


class EntityType(str, Enum):
    package = "package"
    ip = "ip"
    domain = "domain"
    cve = "cve"
    threatactor = "threatactor"
    fraudsignal = "fraudsignal"


class QueryRequest(BaseModel):
    entity: str
    type: EntityType = EntityType.package


class ConfirmRequest(BaseModel):
    entity: str
    type: EntityType = EntityType.package
