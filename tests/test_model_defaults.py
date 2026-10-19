"""Tests for model defaults and LADE_CHEAP environment variable."""

from __future__ import annotations

import os
import pytest

from lade.orchestrator.models import ModelConfig


@pytest.fixture(autouse=True)
def clean_env():
    old = os.environ.pop("LADE_CHEAP", None)
    yield
    if old is not None:
        os.environ["LADE_CHEAP"] = old
    else:
        os.environ.pop("LADE_CHEAP", None)


def test_default_models() -> None:
    os.environ.pop("LADE_CHEAP", None)
    cfg = ModelConfig.from_args()
    assert cfg.planner == "claude-opus-5-5"
    assert cfg.analyst == "claude-opus-5-5"
    assert cfg.executor == "claude-haiku-5-5"


def test_lade_cheap_models() -> None:
    os.environ["LADE_CHEAP"] = "1"
    cfg = ModelConfig.from_args()
    assert cfg.planner == "claude-sonnet-5-5"
    assert cfg.analyst == "claude-sonnet-5-5"
    assert cfg.executor == "claude-haiku-5-5"


def test_explicit_overrides_win_over_cheap() -> None:
    os.environ["LADE_CHEAP"] = "1"
    cfg = ModelConfig.from_args(
        planner_model="custom-planner",
        executor_model="custom-executor",
        analyst_model="custom-analyst",
    )
    assert cfg.planner == "custom-planner"
    assert cfg.analyst == "custom-analyst"
    assert cfg.executor == "custom-executor"
