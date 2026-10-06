#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  tests/security.py
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

"""多租户能力鉴权的安全回归测试。"""

import operator
import pickle
import unittest

import rule_engine.engine as engine
import rule_engine.errors as errors
import rule_engine.types as types

TENANT_A = 'tenant-a'
TENANT_B = 'tenant-b'

SSN_CAP = engine.field_capability('Person', 'ssn')
AUDIT_CAP = engine.function_capability('audit')


def _resolver_read_ssn(thing, name):
    # 业务方注册的解析器：规则只写出一个普通符号名，却间接读取受保护字段
    return thing['employee']['ssn']


def _fn_audit(value):
    return 'AUDIT:' + str(value)


def _fn_last4(value):
    return str(value)[-4:]


class SecurityTestBase(unittest.TestCase):
    def setUp(self):
        self.registry = engine.SecurityRegistry()
        self.authorizer = engine.StaticAuthorizer()

        person = types.DataType.OBJECT(
                'Person',
                attributes={
                        'name': types.DataType.STRING,
                        'ssn': types.DataType.STRING,
                        'tags': types.DataType.ARRAY(types.DataType.STRING),
                },
                accessor=operator.getitem
        )
        # ssn 是仅管理员可见的字段
        self.registry.protect_object_attributes(person, 'ssn')
        self.person = person
        self.type_map = {'employee': person, 'Person': person}

        self.registry.register_resolver(
                TENANT_A, 'secret_profile', _resolver_read_ssn, capabilities=[SSN_CAP]
        )
        self.registry.register_function(
                TENANT_A,
                'audit',
                _fn_audit,
                return_type=types.DataType.STRING,
                argument_types=(types.DataType.STRING,),
                capabilities=[AUDIT_CAP]
        )
        self.registry.register_function(
                TENANT_A,
                'last4',
                _fn_last4,
                return_type=types.DataType.STRING,
                argument_types=(types.DataType.STRING,),
                capabilities=[SSN_CAP]
        )
        self.registry.register_derived_attribute(
                TENANT_A,
                'ssn_tail',
                '$last4(employee.ssn)',
                value_type=types.DataType.STRING,
                capabilities=[SSN_CAP]
        )
        # 与推导式循环变量同名的解析器，用于验证变量遮蔽
        self.registry.register_resolver(
                TENANT_A, 'x', _resolver_read_ssn, capabilities=[SSN_CAP]
        )

        self.thing = {'employee': {'name': 'alice', 'ssn': '123-45-6789', 'tags': ('vip',)}}
        self.authorizer.grant(TENANT_A, 'admin', SSN_CAP, AUDIT_CAP)

    def context(self, tenant_id=TENANT_A, principal='admin'):
        return engine.Context(
                tenant_id=tenant_id,
                principal=principal,
                registry=self.registry,
                authorizer=self.authorizer,
                type_resolver=self.type_map,
                resolver=engine.resolve_item
        )

    def assertDenied(self, text, *, principal='bob', tenant_id=TENANT_A, categories=('field',)):
        try:
            engine.Rule(text, context=self.context(tenant_id=tenant_id, principal=principal))
        except errors.CapabilityDeniedError as error:
            self.assertEqual(tuple(error.missing_categories), tuple(categories))
            # 拒绝消息只能包含能力类别，不得带出字段名/解析器名/函数名
            message = error.message
            for secret in ('ssn', 'secret_profile', 'last4', 'audit'):
                self.assertNotIn(secret, message)
            return error
        self.fail('rule {!r} was not denied'.format(text))


class CapabilityDeclarationTests(SecurityTestBase):
    def test_resolver_requires_capabilities(self):
        with self.assertRaises(ValueError):
            self.registry.register_resolver(TENANT_A, 'empty', _resolver_read_ssn, capabilities=())

    def test_function_requires_capabilities(self):
        with self.assertRaises(ValueError):
            self.registry.register_function(TENANT_A, 'empty', _fn_audit, capabilities=())

    def test_derived_requires_capabilities(self):
        with self.assertRaises(ValueError):
            self.registry.register_derived_attribute(TENANT_A, 'empty', '1', capabilities=())

    def test_unknown_capability_category_rejected(self):
        with self.assertRaises(ValueError):
            self.registry.register_resolver(TENANT_A, 'bad', _resolver_read_ssn, capabilities=['bogus:x'])

    def test_context_requires_identity_and_authorizer(self):
        with self.assertRaises(ValueError):
            engine.Context(tenant_id=TENANT_A, principal='admin', registry=self.registry)
        with self.assertRaises(ValueError):
            engine.Context(registry=self.registry, authorizer=self.authorizer)


class CompileTimeDenialTests(SecurityTestBase):
    def test_direct_protected_field_denied(self):
        self.assertDenied('employee.ssn == "x"')

    def test_indirect_resolver_denied(self):
        # 看似普通的符号经注册解析器间接读取 ssn
        self.assertDenied('secret_profile == "x"')

    def test_registered_function_denied(self):
        self.assertDenied('$audit(employee.name) == "x"', categories=('function',))

    def test_nested_function_argument_denied(self):
        # 外层内置函数 $split 无需能力，但内层注册函数的依赖仍被整条收集
        self.assertDenied('$split($audit(employee.name), ":")[0] == "x"', categories=('function',))

    def test_function_reaching_protected_field_denied(self):
        self.assertDenied('$last4(employee.ssn) == "6789"')

    def test_derived_attribute_denied(self):
        self.assertDenied('ssn_tail == "6789"')

    def test_short_circuit_and_branch_denied(self):
        # 右侧运行时不会执行，但编译期仍必须拒绝
        self.assertDenied('false and employee.ssn == "x"')

    def test_short_circuit_or_branch_denied(self):
        self.assertDenied('true or employee.ssn == "x"')

    def test_dynamic_ternary_both_branches_checked(self):
        self.assertDenied('employee.name == "z" ? employee.ssn : "x"')
        self.assertDenied('employee.name == "z" ? "x" : employee.ssn')

    def test_comprehension_body_denied(self):
        self.assertDenied('$any([employee.ssn for v in [1, 2]])')

    def test_constant_folded_dead_branch_is_safe(self):
        # 条件为常量时不可达分支在编译期被物理折叠，永不执行，故允许
        rule = engine.Rule('false ? employee.ssn : "ok"', context=self.context(principal='bob'))
        self.assertEqual(rule.evaluate(self.thing), 'ok')

    def test_authorized_admin_allowed(self):
        rule = engine.Rule('employee.ssn == "123-45-6789"', context=self.context())
        self.assertTrue(rule.matches(self.thing))
        rule = engine.Rule('secret_profile == "123-45-6789"', context=self.context())
        self.assertTrue(rule.matches(self.thing))
        rule = engine.Rule('ssn_tail == "6789"', context=self.context())
        self.assertTrue(rule.matches(self.thing))
        rule = engine.Rule('$audit(employee.name) == "AUDIT:alice"', context=self.context())
        self.assertTrue(rule.matches(self.thing))

    def test_comprehension_loop_variable_shadows_resolver(self):
        # 解析器 'x' 需要 ssn 能力，但推导式体内的 x 是循环变量，不应被收集
        rule = engine.Rule('$any([x for x in [1, 2] if x > 0])', context=self.context(principal='bob'))
        self.assertTrue(rule.matches(self.thing))


class RuntimeEnforcementTests(SecurityTestBase):
    def test_revoked_field_capability_rejected_on_next_evaluation(self):
        rule = engine.Rule('employee.ssn == "123-45-6789"', context=self.context())
        self.assertTrue(rule.matches(self.thing))
        self.authorizer.revoke(TENANT_A, 'admin', SSN_CAP)
        with self.assertRaises(errors.CapabilityDeniedError):
            rule.matches(self.thing)

    def test_revoked_function_capability_rejected_on_next_evaluation(self):
        rule = engine.Rule('$audit(employee.name) == "AUDIT:alice"', context=self.context())
        self.assertTrue(rule.matches(self.thing))
        self.authorizer.revoke(TENANT_A, 'admin', AUDIT_CAP)
        try:
            rule.evaluate(self.thing)
        except errors.CapabilityDeniedError as error:
            self.assertEqual(error.missing_categories, ('function',))
        else:
            self.fail('evaluation after function revoke succeeded')

    def test_revoked_resolver_capability_rejected_on_next_evaluation(self):
        rule = engine.Rule('secret_profile == "123-45-6789"', context=self.context())
        self.assertTrue(rule.matches(self.thing))
        self.authorizer.revoke(TENANT_A, 'admin', SSN_CAP)
        with self.assertRaises(errors.CapabilityDeniedError):
            rule.evaluate(self.thing)

    def test_re_grant_restores_access(self):
        rule = engine.Rule('employee.ssn == "123-45-6789"', context=self.context())
        self.assertTrue(rule.matches(self.thing))
        self.authorizer.revoke(TENANT_A, 'admin', SSN_CAP)
        with self.assertRaises(errors.CapabilityDeniedError):
            rule.evaluate(self.thing)
        self.authorizer.grant(TENANT_A, 'admin', SSN_CAP)
        self.assertTrue(rule.matches(self.thing))


class RuleCacheIsolationTests(SecurityTestBase):
    def test_cached_rule_does_not_share_authorization(self):
        text = 'employee.ssn == "123-45-6789"'
        admin_context = self.context()
        self.assertTrue(engine.Rule(text, context=admin_context).matches(self.thing))
        # 管理员已编译并缓存该文本，低权限调用者使用自己的上下文时仍被拒绝
        with self.assertRaises(errors.CapabilityDeniedError):
            engine.Rule(text, context=self.context(principal='bob'))

    def test_cache_hit_is_re_authorized_after_revocation(self):
        text = 'employee.ssn == "123-45-6789"'
        context = self.context()
        engine.Rule(text, context=context)
        self.assertIn(text, context._rule_cache)
        self.authorizer.revoke(TENANT_A, 'admin', SSN_CAP)
        # 即使 AST 已缓存，重新构造规则时授权结论必须重新计算
        with self.assertRaises(errors.CapabilityDeniedError):
            engine.Rule(text, context=context)

    def test_cache_does_not_cross_tenants(self):
        # 租户 B 注册了同名解析器但属于不同租户，其授权与缓存与租户 A 完全隔离
        self.registry.register_resolver(TENANT_B, 'secret_profile', _resolver_read_ssn, capabilities=[SSN_CAP])
        self.authorizer.grant(TENANT_B, 'admin', SSN_CAP)
        rule_a = engine.Rule('secret_profile == "123-45-6789"', context=self.context(TENANT_A, 'admin'))
        rule_b = engine.Rule('secret_profile == "123-45-6789"', context=self.context(TENANT_B, 'admin'))
        self.assertTrue(rule_a.matches(self.thing))
        self.assertTrue(rule_b.matches(self.thing))
        # 撤回租户 A 的授权不影响租户 B
        self.authorizer.revoke(TENANT_A, 'admin', SSN_CAP)
        with self.assertRaises(errors.CapabilityDeniedError):
            rule_a.evaluate(self.thing)
        self.assertTrue(rule_b.matches(self.thing))


class TenantIsolationTests(SecurityTestBase):
    def setUp(self):
        super().setUp()
        self.authorizer.grant(TENANT_B, 'admin', SSN_CAP, AUDIT_CAP)

    def test_other_tenant_cannot_resolve_function(self):
        rule = engine.Rule('$audit("x") == "AUDIT:x"', context=self.context(TENANT_B, 'admin'))
        with self.assertRaises(errors.SymbolResolutionError):
            rule.evaluate({})

    def test_other_tenant_cannot_resolve_derived(self):
        with self.assertRaises(errors.SymbolResolutionError):
            engine.Rule('ssn_tail == "x"', context=self.context(TENANT_B, 'admin'))

    def test_other_tenant_cannot_resolve_tenant_resolver(self):
        with self.assertRaises(errors.SymbolResolutionError):
            engine.Rule('secret_profile == "x"', context=self.context(TENANT_B, 'admin'))


class ErrorMessageTests(SecurityTestBase):
    def test_unknown_attribute_suggestion_hides_protected_field(self):
        try:
            engine.Rule('employee.ssx == "x"', context=self.context(principal='bob'))
        except errors.ObjectAttributeError as error:
            self.assertNotEqual(error.suggestion, 'ssn')
        else:
            self.fail('expected ObjectAttributeError')
        # 管理员仍能得到受保护字段的拼写建议
        try:
            engine.Rule('employee.ssx == "x"', context=self.context())
        except errors.ObjectAttributeError as error:
            self.assertEqual(error.suggestion, 'ssn')
        else:
            self.fail('expected ObjectAttributeError')

    def test_denial_message_lists_only_categories(self):
        error = self.assertDenied('employee.ssn == "x"')
        self.assertIn('field', error.message)
        self.assertNotIn('Person', error.message)


class UnsecuredModeTests(SecurityTestBase):
    def test_protected_marker_ignored_without_registry(self):
        # 未启用安全模式时，受保护标记不影响原有读取行为
        context = engine.Context(type_resolver=self.type_map, resolver=engine.resolve_item)
        rule = engine.Rule('employee.ssn == "123-45-6789"', context=context)
        self.assertTrue(rule.matches(self.thing))


class SecuritySerializationTests(SecurityTestBase):
    def test_context_pickle_round_trip(self):
        context = self.context()
        rule = engine.Rule('employee.ssn == "123-45-6789"', context=context)
        self.assertTrue(rule.matches(self.thing))
        # 先撤回权限，再序列化/恢复：恢复出的上下文仍必须执行鉴权
        self.authorizer.revoke(TENANT_A, 'admin', SSN_CAP)
        restored = pickle.loads(pickle.dumps(context))
        with self.assertRaises(errors.CapabilityDeniedError):
            engine.Rule('employee.ssn == "123-45-6789"', context=restored)

    def test_context_pickle_preserves_tenant_isolation(self):
        context = self.context(TENANT_B, 'admin')
        restored = pickle.loads(pickle.dumps(context))
        self.assertEqual(restored.tenant_id, TENANT_B)
        # 租户 B 看不到租户 A 注册的解析器
        with self.assertRaises(errors.SymbolResolutionError):
            engine.Rule('secret_profile == "x"', context=restored)


if __name__ == '__main__':
    unittest.main()
