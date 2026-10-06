#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/authz.py
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the project nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

"""
能力声明与调用者授权的辅助原语。

Resolvers, functions and derived attributes declare the capabilities they require; callers supply their granted
capabilities at compile or evaluation time. This module holds the shared normalization helpers so the declaration
points (context, builtins, attribute resolver, object type definitions) stay free of each other's imports.
"""

from typing import Callable, Iterable

# a capability declaration: a single category string or an iterable of category strings
CapabilityDeclaration = 'str | Iterable[str] | None'
# the caller's granted capabilities: an iterable of category strings, or a zero-argument callable returning one (a
# callable is re-invoked for every check so permissions revoked mid-evaluation take effect immediately)
Grants = 'Iterable[str] | Callable[[], Iterable[str]] | None'

_EMPTY: frozenset[str] = frozenset()

def normalize_capabilities(declaration: 'str | Iterable[str] | None') -> frozenset[str]:
    """项目内部接口说明。"""
    if declaration is None:
        return _EMPTY
    if isinstance(declaration, str):
        return frozenset((declaration,))
    capabilities = frozenset(declaration)
    for capability in capabilities:
        if not isinstance(capability, str):
            raise TypeError('capabilities must be strings, not ' + type(capability).__name__)
    return capabilities

def grants_provider(grants: 'Iterable[str] | Callable[[], Iterable[str]] | None') -> Callable[[], frozenset[str]]:
    """项目内部接口说明。"""
    if grants is None:
        return lambda: _EMPTY
    if callable(grants):
        return lambda: normalize_capabilities(grants())
    # re-normalize on every call so a mutable set of grants reflects permissions revoked while a rule is running
    return lambda: normalize_capabilities(grants)
