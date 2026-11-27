"""Shared fixtures: an isolated fake HOME, project root and approved root per test."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from mini.config import DEFAULT_PROJECT_ROOT, load_config

POLICY = DEFAULT_PROJECT_ROOT / "config" / "policy.yaml"


@pytest.fixture
def env_tree(tmp_path: Path) -> SimpleNamespace:
    home = tmp_path / "home"
    mini_root = tmp_path / "mini_root"
    project = home / "projects" / "demo"
    outside = tmp_path / "outside"

    files = {
        project / "README.md": "# Demo project\n\nStatus: draft\n",
        project / "notes" / "todo.md": "- write report\n",
        project / ".env": "OPENAI_API_KEY=sk-test\n",
        project / ".env.local": "X=1\n",
        project / "server.pem": "-----BEGIN PRIVATE KEY-----\n",
        project / "deploy.key": "k\n",
        project / "gcp-credentials.json": "{}",
        project / "oauth_token.json": "{}",
        project / ".git" / "config": "[core]\n",
        project / "report.pdf": "%PDF-1.4 fake\n",
        home / ".ssh" / "id_rsa": "PRIVATE\n",
        home / ".aws" / "credentials": "[default]\n",
        home / ".mini" / "secrets" / "gmail_token.json": '{"refresh_token": "x"}',
        home / ".mini" / "trusted_devices.json": '{"devices": []}',
        outside / "secret.txt": "outside the root\n",
    }
    for p, text in files.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    mini_root.mkdir()
    return SimpleNamespace(tmp=tmp_path, home=home, mini_root=mini_root, project=project, outside=outside)


@pytest.fixture
def make_cfg(env_tree: SimpleNamespace):
    def _make(**overrides):
        kw = dict(project_root=env_tree.mini_root, home=env_tree.home, env={},
                  approved_roots=[env_tree.project])
        kw.update(overrides)
        return load_config(POLICY, **kw)
    return _make


@pytest.fixture
def cfg(make_cfg):
    return make_cfg()
