from dataclasses import dataclass
from typing import Optional
from urllib.parse import ParseResult


@dataclass
class InstanceFilehost:
    instance_id: str
    url: ParseResult
    filehost_path: Optional[ParseResult]
