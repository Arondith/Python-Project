from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Settings:
    database_path: str = "./data/logscope.db"
    failure_threshold: int = 5
    window_minutes: int = 10


def load_settings() -> Settings:
    threshold = int(os.getenv("LOGSCOPE_FAILURE_THRESHOLD", "5"))
    window_minutes = int(os.getenv("LOGSCOPE_WINDOW_MINUTES", "10"))

    if threshold < 2:
        raise ValueError("LOGSCOPE_FAILURE_THRESHOLD must be at least 2")

    if window_minutes < 1:
        raise ValueError("LOGSCOPE_WINDOW_MINUTES must be at least 1")

    return Settings(
        database_path=os.getenv("LOGSCOPE_DB", "./data/logscope.db"),
        failure_threshold=threshold,
        window_minutes=window_minutes,
    )
