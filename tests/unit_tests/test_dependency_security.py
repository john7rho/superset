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

from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_IN = REPO_ROOT / "requirements" / "base.in"


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


def test_sqlparse_cve_2023_30608() -> None:
    """CVE-2023-30608: ReDoS in SQL parser regular expression.

    The SQL parser in sqlparse < 0.4.4 contains a regular expression
    vulnerable to Regular Expression Denial of Service (ReDoS).
    Fixed in sqlparse >= 0.4.4.
    """
    req = _get_requirement("sqlparse")
    vulnerable_versions = ["0.4.3", "0.4.2", "0.4.1", "0.4.0", "0.3.1", "0.1.15"]
    for ver in vulnerable_versions:
        assert Version(ver) not in req.specifier, (
            f"sqlparse constraint '{req.specifier}' allows vulnerable "
            f"version {ver} (CVE-2023-30608)"
        )
    # At least one patched version must be installable
    assert Version("0.4.4") in req.specifier or Version("0.5.0") in req.specifier, (
        f"sqlparse constraint '{req.specifier}' does not allow any patched "
        f"version (CVE-2023-30608)"
    )
