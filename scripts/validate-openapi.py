#!/usr/bin/env python3
"""离线检查 OpenAPI 结构、本地引用及关键绑定字段；不替代 HTTP/真机测试。

仅使用 Python 标准库，CI 不需要网络安装校验依赖。
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"重复 JSON 键：{key}")
        result[key] = value
    return result


def local_refs(document, node):
    if isinstance(node, dict):
        if "$ref" in node:
            reference = node["$ref"]
            require(isinstance(reference, str) and reference.startswith("#/"),
                    "契约只允许本地 JSON Pointer 引用")
            target = document
            for segment in reference[2:].split("/"):
                key = segment.replace("~1", "/").replace("~0", "~")
                require(isinstance(target, dict) and key in target,
                        f"失效引用：{reference}")
                target = target[key]
        for value in node.values():
            local_refs(document, value)
    elif isinstance(node, list):
        for value in node:
            local_refs(document, value)


def validate(document):
    require(document.get("openapi") == "3.1.0", "要求 OpenAPI 3.1.0")
    require(document.get("paths"), "缺少公开接口")
    local_refs(document, document)
    schemes = document.get("components", {}).get("securitySchemes", {})
    for path, item in document["paths"].items():
        require(path.startswith("/qm/v1/"), f"非 QM v1 路径：{path}")
        for method, operation in item.items():
            if method not in METHODS:
                continue
            require(operation.get("responses"), f"缺少响应：{method} {path}")
            for requirement in operation.get("security", document.get("security", [])):
                require(all(name in schemes for name in requirement),
                        f"未定义认证方案：{method} {path}")


def binding_contract(document):
    schemas = document["components"]["schemas"]
    for name in ("Code", "BindRequest", "BatchItem"):
        code = schemas[name]["properties"]["code"]
        require(code["type"] == "string", f"{name} 不能把绑定码转为整数")
        pattern = code["pattern"]
        require(re.fullmatch(pattern, "000123") is not None,
                f"{name} 丢失前导零")
        for invalid in ("12345", "1234567", "１２３４５６", "12345a"):
            require(re.fullmatch(pattern, invalid) is None, f"{name} 接受非法码")
    require("code" not in schemas["Code"]["required"], "已绑定手机不得必需返回码")
    require(set(schemas["Peer"]["properties"]["online"]["type"]) == {"boolean", "null"},
            "presence 必须能表达未知而不是仅 online/offline")
    require(schemas["BatchRequest"]["properties"]["items"]["maxItems"] == 200,
            "批量资源边界必须和服务实现一致")
    require({"role", "device_id", "service_scope", "bound"}.issubset(schemas["Ensure"]["required"]),
            "ensure 丢失客户端必需字段")
    require(schemas["Relation"]["properties"]["revision"]["type"] == "string",
            "关系版本必须使用十进制字符串")


def main():
    # 检验检查器本身确实拒绝无效/外部引用，避免无效的绿灯。
    for invalid in ({"$ref": "#/missing"}, {"$ref": "https://example.invalid/schema"}):
        try:
            local_refs(invalid, invalid)
        except ValueError:
            pass
        else:
            raise ValueError("引用校验器没有拒绝负样例")
    for path in sorted((ROOT / "api").glob("*.openapi.json")):
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        validate(document)
        if path.name == "binding.openapi.json":
            binding_contract(document)
        print(f"通过：{path.name} 结构、本地引用和认证声明")
    print("绑定码/未知presence/批量/ensure契约通过；未执行HTTP或真实设备链路。")


if __name__ == "__main__":
    main()
