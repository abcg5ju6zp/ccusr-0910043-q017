#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/security.py
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

"""多租户规则服务的能力声明、授权与编译/执行期鉴权支持。

业务方向多租户服务注册属性解析器、函数或派生属性时，必须通过
:py:class:`SecurityRegistry` 声明它们运行时所需的*能力*。规则在编译期与执行
期都会结合调用者（租户 + 主体）持有的能力对整条依赖链进行校验，因此一条只
写出普通名称的规则无法通过注册的解析器间接读取仅管理员可见的对象字段。
"""

from __future__ import annotations

import collections.abc
import threading
from typing import Any, Callable, Iterable, Mapping, NamedTuple

from . import errors
from .types import DataType, _DataTypeDef, _FunctionDataTypeDef, _ObjectDataTypeDef

# 能力类别（对外可见）。拒绝信息只引用这些稳定的类别名，绝不带出受保护字段
# 名、解析器键名或函数名，避免错误消息本身成为侧信道。
CATEGORY_FIELD = 'field'
"""类别：读取受保护的对象字段。"""
CATEGORY_RESOLVER = 'resolver'
"""类别：调用业务方注册的（可能读取受保护数据的）属性解析器。"""
CATEGORY_FUNCTION = 'function'
"""类别：调用业务方注册的函数。"""
CATEGORY_DERIVED = 'derived'
"""类别：读取业务方注册的派生属性。"""

CATEGORY_ALL = (CATEGORY_FIELD, CATEGORY_RESOLVER, CATEGORY_FUNCTION, CATEGORY_DERIVED)


def field_capability(object_type_name: str, attribute_name: str) -> str:
    """返回读取某 OBJECT 类型上某个字段所需的能力标识。"""
    return '{}:{}:{}'.format(CATEGORY_FIELD, object_type_name, attribute_name)


def resolver_capability(key: str) -> str:
    """返回根符号动态解析器所需的能力标识。"""
    return '{}:{}'.format(CATEGORY_RESOLVER, key)


def function_capability(name: str) -> str:
    """返回业务方注册函数所需的能力标识。"""
    return '{}:{}'.format(CATEGORY_FUNCTION, name)


def derived_capability(name: str) -> str:
    """返回派生属性所需的能力标识。"""
    return '{}:{}'.format(CATEGORY_DERIVED, name)


def category_of(capability: str) -> str:
    """返回能力标识所属的类别（拒绝信息里唯一允许暴露的部分）。"""
    return capability.split(':', 1)[0]


def _categories(capabilities: Iterable[str]) -> tuple[str, ...]:
    # 去重并保持 CATEGORY_ALL 的稳定顺序，避免把能力数量/内容编码进错误文本
    present = {category_of(cap) for cap in capabilities}
    return tuple(category for category in CATEGORY_ALL if category in present)


class AuthorizationContext(NamedTuple):
    """一次规则求值的授权上下文：租户标识与调用者主体标识。"""
    tenant_id: str
    principal: str


class Authorizer(object):
    """授权者接口。

    实现方根据 *context*（租户、调用者）返回其持有的全部能力集合。引擎在
    **编译期和每一次求值时**都会调用本方法，因此不允许实现方把结论长期缓存
    在引擎侧；权限一旦在这里被撤回，下一次求值立即生效。
    """

    def capabilities_for(self, context: AuthorizationContext) -> collections.abc.Collection[str]:
        raise NotImplementedError()


class StaticAuthorizer(Authorizer):
    """一个简单的内存授权者：按 ``(tenant_id, principal)`` 授予能力集合。

    授权表可在运行时通过 :py:meth:`grant` / :py:meth:`revoke` 修改，撤回对
    后续求值立即生效（引擎不缓存授权结果）。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: dict[tuple[str, str], set[str]] = {}

    def __getstate__(self) -> dict[str, Any]:
        with self._lock:
            return {'_grants': {key: set(value) for key, value in self._grants.items()}}

    def __setstate__(self, state: Mapping[str, Any]) -> None:
        self._lock = threading.Lock()
        self._grants = state['_grants']

    def grant(self, tenant_id: str, principal: str, *capabilities: str) -> None:
        with self._lock:
            self._grants.setdefault((tenant_id, principal), set()).update(capabilities)

    def revoke(self, tenant_id: str, principal: str, *capabilities: str) -> None:
        with self._lock:
            granted = self._grants.get((tenant_id, principal))
            if granted is None:
                return
            if not capabilities:
                granted.clear()
                return
            granted.difference_update(capabilities)

    def capabilities_for(self, context: AuthorizationContext) -> frozenset[str]:
        with self._lock:
            return frozenset(self._grants.get((context.tenant_id, context.principal), ()))


class RegisteredResolver(NamedTuple):
    """业务方注册的根符号解析器及其能力声明。"""
    key: str
    resolver: Callable[[Any, str], Any]
    capabilities: frozenset[str]


class RegisteredFunction(NamedTuple):
    """业务方注册的函数及其能力声明。"""
    name: str
    function: Callable[..., Any]
    function_type: _FunctionDataTypeDef
    capabilities: frozenset[str]


class RegisteredDerivedAttribute(NamedTuple):
    """业务方注册的派生属性（由其它表达式计算得到）及其能力声明。"""
    name: str
    expression_text: str
    value_type: _DataTypeDef
    capabilities: frozenset[str]


class SecurityRegistry(object):
    """按租户隔离的解析器 / 函数 / 派生属性注册表。

    所有注册项都必须显式声明它们运行时需要的能力；未声明能力的注册项不可
    能被规则触达。注册表按 *tenant_id* 隔离，一个租户注册的名称对其他租户
    不可见。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._resolvers: dict[str, dict[str, RegisteredResolver]] = {}
        self._functions: dict[str, dict[str, RegisteredFunction]] = {}
        self._derived: dict[str, dict[str, RegisteredDerivedAttribute]] = {}

    def __getstate__(self) -> dict[str, Any]:
        with self._lock:
            return {
                    '_resolvers': self._resolvers,
                    '_functions': self._functions,
                    '_derived': self._derived,
            }

    def __setstate__(self, state: Mapping[str, Any]) -> None:
        self._lock = threading.Lock()
        self._resolvers = state['_resolvers']
        self._functions = state['_functions']
        self._derived = state['_derived']

    @staticmethod
    def _require_capabilities(capabilities: Iterable[str] | None) -> frozenset[str]:
        declared = frozenset(capabilities or ())
        if not declared:
            raise ValueError('a security capability must be declared at registration time')
        for capability in declared:
            if category_of(capability) not in CATEGORY_ALL:
                raise ValueError('unknown capability category: ' + category_of(capability))
        return declared

    def register_resolver(
            self,
            tenant_id: str,
            key: str,
            resolver: Callable[[Any, str], Any],
            capabilities: Iterable[str]
    ) -> None:
        """注册一个根符号解析器，并声明它可能触及的全部能力。"""
        caps = self._require_capabilities(capabilities)
        with self._lock:
            self._resolvers.setdefault(tenant_id, {})[key] = RegisteredResolver(key, resolver, caps)

    def register_function(
            self,
            tenant_id: str,
            name: str,
            function: Callable[..., Any],
            *,
            return_type: _DataTypeDef = DataType.UNDEFINED,
            argument_types: tuple[_DataTypeDef, ...] | _DataTypeDef = DataType.UNDEFINED,
            minimum_arguments: int | None = None,
            capabilities: Iterable[str]
    ) -> None:
        """注册一个可在 ``$name(...)`` 位置调用的函数，并声明其能力。"""
        caps = self._require_capabilities(capabilities)
        function_type = DataType.FUNCTION(
                name,
                return_type=return_type,
                argument_types=argument_types,
                minimum_arguments=minimum_arguments
        )
        with self._lock:
            self._functions.setdefault(tenant_id, {})[name] = RegisteredFunction(name, function, function_type, caps)

    def register_derived_attribute(
            self,
            tenant_id: str,
            name: str,
            expression_text: str,
            *,
            value_type: _DataTypeDef = DataType.UNDEFINED,
            capabilities: Iterable[str]
    ) -> None:
        """注册一个派生属性（其值由另一条表达式计算），并声明其能力。

        派生属性的依赖链在规则编译期会被一并展开：派生属性表达式自身需要
        的全部能力会合并进使用方规则，因此无法通过派生属性间接提权。
        """
        caps = self._require_capabilities(capabilities)
        with self._lock:
            self._derived.setdefault(tenant_id, {})[name] = RegisteredDerivedAttribute(
                    name, expression_text, value_type, caps
            )

    def protect_object_attributes(self, object_type: _ObjectDataTypeDef, *attribute_names: str) -> _ObjectDataTypeDef:
        """把 OBJECT schema 上的字段标记为仅管理员（或持能力者）可读。

        标记直接记录在 schema 实例的 ``protected_attributes`` 槽位上，编译
        期据此生成 ``field:`` 能力要求，执行期访问该字段时还会再次校验。
        """
        for attribute_name in attribute_names:
            if attribute_name not in object_type.attributes:
                raise KeyError('unknown attribute: ' + attribute_name)
        object_type.protected_attributes = frozenset(object_type.protected_attributes | frozenset(attribute_names))
        return object_type

    def resolver(self, tenant_id: str, key: str) -> RegisteredResolver | None:
        with self._lock:
            reg = self._resolvers.get(tenant_id)
            return reg.get(key) if reg else None

    def function(self, tenant_id: str, name: str) -> RegisteredFunction | None:
        with self._lock:
            reg = self._functions.get(tenant_id)
            return reg.get(name) if reg else None

    def derived(self, tenant_id: str, name: str) -> RegisteredDerivedAttribute | None:
        with self._lock:
            reg = self._derived.get(tenant_id)
            return reg.get(name) if reg else None

    def resolver_keys(self, tenant_id: str) -> tuple[str, ...]:
        with self._lock:
            reg = self._resolvers.get(tenant_id)
            return tuple(reg) if reg else ()


def protected_attributes(object_type: _DataTypeDef) -> frozenset[str]:
    """返回 OBJECT schema 上被标记为受保护的字段名集合。"""
    if not isinstance(object_type, _ObjectDataTypeDef):
        return frozenset()
    return frozenset(object_type.protected_attributes)


def enforce(granted: collections.abc.Collection[str], required: collections.abc.Collection[str]) -> None:
    """校验调用者持有全部所需能力，否则抛出只含能力类别的拒绝错误。"""
    granted_set = frozenset(granted)
    missing = frozenset(cap for cap in required if cap not in granted_set)
    if missing:
        raise errors.CapabilityDeniedError(_categories(missing))
