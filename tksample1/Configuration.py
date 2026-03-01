import json
import pathlib
from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class Configuration:
    """Configuration class to manage application settings."""

    downdir: str
    tmpdir: str

    @classmethod
    def from_dict(cls, data: dict) -> "Configuration":
        """Create Configuration instance from a dictionary."""
        return cls(downdir=data.get("downdir", ""), tmpdir=data.get("tmpdir", ""))

    def to_dict(self) -> dict:
        """Convert Configuration to dictionary."""
        return asdict(self)

    @classmethod
    def load(cls, config_path: pathlib.Path) -> "Configuration":
        """Load configuration from file."""
        if config_path.exists():
            with open(config_path, "r") as f:
                data = json.load(f)
                return cls.from_dict(data)
        return cls.default()

    def save(self, config_path: pathlib.Path) -> None:
        """Save configuration to file."""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def default(cls) -> "Configuration":
        """Create default configuration with sensible defaults."""
        home = pathlib.Path.home()
        return cls(
            downdir=str(home / "Downloads"), tmpdir=str(home / ".millegrilles" / "tmp")
        )
