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

import re
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version

from superset.utils import json

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_IN = REPO_ROOT / "requirements" / "base.in"
FRONTEND_PACKAGE_JSON = REPO_ROOT / "superset-frontend" / "package.json"
FRONTEND_LOCK_JSON = REPO_ROOT / "superset-frontend" / "package-lock.json"


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


def _npm_caret_min_version(spec: str) -> Version:
    """Return the minimum version allowed by an npm caret (``^``) range.

    Only handles the ``^MAJOR.MINOR.PATCH`` form used in this repo.
    """
    match = re.match(r"\^(\d+\.\d+\.\d+.*)$", spec)
    if not match:
        raise ValueError(f"Unsupported npm version spec: {spec}")
    return Version(match.group(1))


def _get_npm_dependency_version(package_name: str) -> str:
    """Return the version range for *package_name* from package.json."""
    data = json.loads(FRONTEND_PACKAGE_JSON.read_text())
    for section in ("dependencies", "devDependencies"):
        version = data.get(section, {}).get(package_name)
        if version is not None:
            return version
    raise AssertionError(f"{package_name} not found in {FRONTEND_PACKAGE_JSON}")


def _get_npm_resolved_version(package_name: str) -> Version:
    """Return the resolved version of *package_name* from the npm lockfile."""
    data = json.loads(FRONTEND_LOCK_JSON.read_text())
    key = f"node_modules/{package_name}"
    if key in (packages := data.get("packages", {})):
        return Version(packages[key]["version"])
    raise AssertionError(f"{package_name} not found in {FRONTEND_LOCK_JSON}")


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


def test_lodash_cve_2021_23337() -> None:
    """CVE-2021-23337 (HIGH): Command injection via lodash.template.

    Fixed in lodash >= 4.17.21. The lower bound of the lodash dependency
    in superset-frontend/package.json must exclude vulnerable versions.
    """
    spec = _get_npm_dependency_version("lodash")
    min_version = _npm_caret_min_version(spec)
    cve_fix_version = Version("4.17.21")

    assert min_version >= cve_fix_version, (
        f"lodash constraint '{spec}' allows versions below {cve_fix_version} "
        f"(CVE-2021-23337)"
    )

    resolved = _get_npm_resolved_version("lodash")
    assert resolved >= cve_fix_version, (
        f"lodash resolved to {resolved} in lockfile, which is below "
        f"{cve_fix_version} (CVE-2021-23337)"
    )
