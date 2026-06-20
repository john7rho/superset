# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Tests to verify that dependency version constraints cover known CVEs."""

from __future__ import annotations

import json
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_IN = REPO_ROOT / "requirements" / "base.in"
FRONTEND_PACKAGE_JSON = REPO_ROOT / "superset-frontend" / "package.json"


def _get_requirement(package_name: str) -> Requirement:
    """Parse the requirement spec for *package_name* from requirements/base.in."""
    for line in BASE_IN.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        try:
            req = Requirement(stripped)
        except (ValueError, TypeError):
            continue
        if req.name.lower() == package_name.lower():
            return req
    raise AssertionError(f"{package_name} not found in {BASE_IN}")


def test_urllib3_cve_2023_43804() -> None:
    """CVE-2023-43804: Cookie header not stripped on cross-origin redirects.

    Fixed in urllib3 >= 2.0.6 (2.x branch) and >= 1.26.17 (1.x branch).
    The lower bound of the urllib3 requirement must exclude vulnerable versions.
    """
    req = _get_requirement("urllib3")
    vulnerable_versions = ["2.0.5", "2.0.4", "2.0.0", "1.26.16", "1.26.0"]
    for ver in vulnerable_versions:
        assert Version(ver) not in req.specifier, (
            f"urllib3 constraint '{req.specifier}' allows vulnerable "
            f"version {ver} (CVE-2023-43804)"
        )
    # At least one patched 2.x version must be installable
    assert Version("2.0.6") in req.specifier or any(
        Version(v) in req.specifier for v in ["2.6.3", "2.7.0"]
    ), (
        f"urllib3 constraint '{req.specifier}' does not allow any patched "
        f"2.x version (CVE-2023-43804)"
    )


def _get_npm_override(package_name: str) -> str:
    """Read the npm override constraint for *package_name* from package.json."""
    data = json.loads(FRONTEND_PACKAGE_JSON.read_text())
    overrides = data.get("overrides", {})
    constraint = overrides.get(package_name)
    if constraint is None:
        raise AssertionError(
            f"{package_name} not found in overrides of {FRONTEND_PACKAGE_JSON}"
        )
    if not isinstance(constraint, str):
        raise AssertionError(
            f"{package_name} override is not a simple version string"
        )
    return constraint


def _npm_constraint_rejects(constraint: str, version: str) -> bool:
    """Check if an npm-style constraint rejects a given version.

    Supports >=X.Y.Z style constraints used in overrides.
    """
    req = Requirement(f"dummy{constraint}")
    return Version(version) not in req.specifier


def test_babel_traverse_ghsa_67hx_6x53_jw92() -> None:
    """GHSA-67hx-6x53-jw92 / CVE-2023-45133: arbitrary code execution via
    @babel/traverse path.evaluate().

    Fixed in @babel/traverse >= 7.23.2.
    The npm override must reject all vulnerable versions (<= 7.23.0).
    """
    constraint = _get_npm_override("@babel/traverse")
    vulnerable_versions = ["7.23.0", "7.22.0", "7.20.0", "7.0.0"]
    for ver in vulnerable_versions:
        assert _npm_constraint_rejects(constraint, ver), (
            f"@babel/traverse override '{constraint}' allows vulnerable "
            f"version {ver} (GHSA-67hx-6x53-jw92)"
        )
    # Patched versions must be allowed
    patched_versions = ["7.23.2", "7.24.0", "7.29.7"]
    for ver in patched_versions:
        assert not _npm_constraint_rejects(constraint, ver), (
            f"@babel/traverse override '{constraint}' rejects patched "
            f"version {ver} (GHSA-67hx-6x53-jw92)"
        )
