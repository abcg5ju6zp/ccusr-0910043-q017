# 规则表达式引擎

本项目提供可嵌入服务端的规则解析、类型检查、属性解析和表达式评估能力。生产源码位于 `lib/rule_engine/`，核心回归测试位于 `tests/`。

## 安装

`python3 -m pip install --break-system-packages --no-build-isolation -e .`

## 测试

`python3 -m pytest -q`

## 构建

`python3 -m compileall -q lib/rule_engine`

`python3 -m build --wheel --no-isolation`

## 使用

调用方创建规则并传入普通 Python 对象即可完成本地评估，不需要外部服务。

## 多租户能力鉴权

规则只写出普通名称也可能经业务方注册的解析器、函数或派生属性**间接**读到
仅管理员可见的字段。启用安全模式后，这些注册项必须在注册时声明所需能力，
引擎在**编译期和执行期**结合调用者（租户 + 主体）校验整条依赖链：

```python
from rule_engine.engine import (
        Context, Rule, SecurityRegistry, StaticAuthorizer, field_capability
)

registry = SecurityRegistry()
authorizer = StaticAuthorizer()

# 注册解析器时声明它可能间接读取的受保护字段
registry.register_resolver(
        'tenant-a', 'profile', my_profile_resolver,
        capabilities=[field_capability('Person', 'ssn')]
)

# 构造规则时绑定租户与调用者主体；编译期即按整条依赖链鉴权
context = Context(tenant_id='tenant-a', principal='alice',
                  registry=registry, authorizer=authorizer, ...)
rule = Rule('profile == "..."', context=context)
```

要点：

- 能力分四类：`field:`（受保护对象字段）、`resolver:`（注册解析器）、
  `function:`（注册函数）、`derived:`（派生属性）。受保护字段通过
  `registry.protect_object_attributes(ObjectType, 'ssn')` 标记。
- 编译期遍历**全部** AST 分支收集能力，`and`/`or` 的短路分支、三元两个
  分支、推导式、嵌套函数实参都不会绕过校验。
- 执行期每次求值都重新查询授权者：权限一旦撤回，下一次求值立即失效。
- 编译缓存放于按 `(租户, 主体)` 构建的 `Context` 上，且命中缓存仍重新
  鉴权，不会跨租户/主体复用授权结论。
- 拒绝错误 `CapabilityDeniedError` 只报告缺失的能力**类别**，不带出受保护
  字段名、解析器键名或函数名，避免错误消息侧信道泄露。

