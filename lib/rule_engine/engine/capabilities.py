#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/engine/capabilities.py
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following
#    disclaimer in the documentation and/or other materials provided
#    with the distribution.
#
#

"""编译期能力依赖链分析。

遍历规则 AST 的**全部**节点收集所需能力——包括 ``and`` / ``or`` 中运行时
不会执行的短路分支、三元表达式的两个分支、数组推导式的条件与结果、嵌套函
数调用的实参，以及字面量数组/映射中内嵌的表达式。因此规则无法借由短路或
嵌套结构绕过编译期鉴权。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from .. import ast
from .. import security
from ..ast import binary as _binary
from ..builtins import Builtins

if TYPE_CHECKING:
    from ..types import _DataTypeDef
    from .context import Context


def _object_type_of(node: 'ast.GetAttributeExpression') -> '_DataTypeDef | None':
    return getattr(node, '_object_type', None)


class _CapabilityCollector(object):
    def __init__(self, context: 'Context') -> None:
        self.context = context
        self.required: set[str] = set()
        self._derived_guard: set[str] = set()
        # 推导式当前绑定的变量名栈：这些符号在表达式体内指向循环变量而非根
        # 符号解析器，与运行时 assignments 的遮蔽语义保持一致
        self._bound: dict[str, int] = {}

    def collect(self, node: 'ast.ASTNodeBase') -> frozenset[str]:
        self._visit(node)
        return frozenset(self.required)

    def _add(self, *capabilities: str) -> None:
        self.required.update(capabilities)

    def _visit(self, node: object) -> None:
        if isinstance(node, ast.Statement):
            self._visit(node.expression)
            return

        if isinstance(node, ast.SymbolExpression):
            self._visit_symbol(node)
            return

        if isinstance(node, ast.FunctionCallExpression):
            # 被调用函数自身（可能是 $name 形式的注册函数）及其全部实参
            self._visit(node.function)
            for argument in node.arguments:
                self._visit(argument)
            return

        if isinstance(node, ast.GetAttributeExpression):
            self._visit_attribute(node)
            return

        if isinstance(node, ast.GetItemExpression):
            self._visit(node.container)
            self._visit(node.item)
            return

        if isinstance(node, ast.GetSliceExpression):
            self._visit(node.container)
            self._visit(node.start)
            self._visit(node.stop)
            return

        if isinstance(node, ast.ContainsExpression):
            self._visit(node.container)
            self._visit(node.member)
            return

        if isinstance(node, ast.TernaryExpression):
            # 两个分支都要计入，短路三元不能隐藏依赖
            self._visit(node.condition)
            self._visit(node.case_true)
            self._visit(node.case_false)
            return

        if isinstance(node, ast.ComprehensionExpression):
            # iterable 在变量绑定之外求值；condition 与 result 体内变量名指向
            # 循环元素而非根符号（与运行时 assignments 遮蔽语义一致）
            self._visit(node.iterable)
            self._bound[node.variable] = self._bound.get(node.variable, 0) + 1
            try:
                if node.condition is not None:
                    self._visit(node.condition)
                self._visit(node.result)
            finally:
                remaining = self._bound[node.variable] - 1
                if remaining:
                    self._bound[node.variable] = remaining
                else:
                    self._bound.pop(node.variable, None)
            return

        if isinstance(node, ast.UnaryExpression):
            self._visit(node.right)
            return

        if isinstance(node, _binary.BinaryExpressionBase) or isinstance(node, ast.CoalesceExpression):
            # LogicExpression 在运行时短路，但编译期必须同时计入左、右依赖
            self._visit(node.left)
            self._visit(node.right)
            return

        if isinstance(node, ast.MappingExpression):
            for key, value in node.value:
                self._visit(key)
                self._visit(value)
            return

        if isinstance(node, (ast.ArrayExpression, ast.SetExpression)):
            for member in node.value:
                self._visit(member)
            return

        # 其它字面量（标量、FunctionExpression 等）没有规则级依赖
        return

    def _visit_symbol(self, node: 'ast.SymbolExpression') -> None:
        # 推导式循环变量：由表达式内部绑定，不对应任何注册解析器/派生属性
        if node.scope is None and node.name in self._bound:
            return
        registry = self.context.registry
        if registry is None:
            return
        tenant_id = cast(str, self.context.tenant_id)
        if node.scope == Builtins.scope_name:
            registered_function = registry.function(tenant_id, node.name)
            if registered_function is not None:
                self._add(*registered_function.capabilities)
            return
        # 根符号：派生属性
        derived = registry.derived(tenant_id, node.name)
        if derived is not None:
            self._add(*derived.capabilities)
            self._visit_derived(node.name)
            return
        # 根符号：注册的属性解析器
        registered_resolver = registry.resolver(tenant_id, node.name)
        if registered_resolver is not None:
            self._add(*registered_resolver.capabilities)

    def _visit_derived(self, name: str) -> None:
        if name in self._derived_guard:
            # 派生属性间存在循环引用时不再重复展开，已声明的能力仍会计入
            return
        self._derived_guard.add(name)
        try:
            statement = self.context.compile_derived(name)
        finally:
            self._derived_guard.discard(name)
        self._visit(statement)

    def _visit_attribute(self, node: 'ast.GetAttributeExpression') -> None:
        self._visit(node.object)
        object_type = _object_type_of(node)
        if object_type is None:
            # 无静态 schema 的动态属性访问：其根符号若是注册解析器，解析器
            # 声明的能力已经在上游 SymbolExpression 处计入，此处无需猜测。
            return
        if node.name in security.protected_attributes(object_type):
            self._add(security.field_capability(object_type.name, node.name))


def collect_required_capabilities(statement: 'ast.Statement', context: 'Context') -> frozenset[str]:
    """返回整条规则依赖链上所需的全部能力。"""
    return _CapabilityCollector(context).collect(statement)
