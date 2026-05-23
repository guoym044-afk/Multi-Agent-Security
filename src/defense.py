"""Rule-based defense module for a small multi-agent security demo.

The module is intentionally standalone: it accepts one normalized message
object and returns a decision object with at least ``action`` and ``reason``.
It can also be run directly to evaluate the handcrafted test cases in
``data/defense_test_cases.json``.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Tuple

Message = Dict[str, Any]
DefenseResult = Dict[str, Any]

Action = str
ALLOW: Action = "allow"
BLOCK: Action = "block"
REDACT: Action = "redact"


KEYWORD_RULES: List[Tuple[str, str, List[re.Pattern[str]]]] = [
    (
        "prompt_injection",
        "检测到提示注入或越权改写指令",
        [
            re.compile(r"忽略.{0,12}(之前|以上|上面|所有).{0,12}(规则|指令|要求|系统)", re.I),
            re.compile(r"(ignore|disregard|forget).{0,30}(previous|prior|above|system).{0,30}(instruction|rule|message)", re.I),
            re.compile(r"(绕过|越过|禁用|关闭).{0,12}(安全|审查|规则|防御|过滤)", re.I),
            re.compile(r"\b(bypass|jailbreak|dan mode|developer mode)\b", re.I),
        ],
    ),
    (
        "secret_exfiltration",
        "检测到敏感信息泄露请求",
        [
            re.compile(r"(输出|泄露|打印|展示|告诉|给我|写入).{0,20}(api[_ -]?key|密钥|密码|token|secret|隐藏信息|系统提示词|system prompt)", re.I),
            re.compile(r"(api[_ -]?key|密钥|密码|token|secret|system prompt).{0,20}(输出|泄露|打印|展示|告诉|写入)", re.I),
            re.compile(r"(reveal|exfiltrate|print|dump|show).{0,20}(api[_ -]?key|password|token|secret|system prompt)", re.I),
        ],
    ),
    (
        "covert_or_untrusted_instruction",
        "检测到隐蔽执行或绕过审核的指令",
        [
            re.compile(r"(不要|无需|别).{0,8}(告诉|通知).{0,12}(Reviewer|审查|安全|用户)", re.I),
            re.compile(r"(偷偷|私下|隐藏).{0,12}(执行|加入|写入|发送)", re.I),
            re.compile(r"(base64|编码|加密).{0,12}(输出|发送|绕过|隐藏)", re.I),
        ],
    ),
]


SENSITIVE_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    (
        "api_key_assignment",
        re.compile(
            r"(?P<prefix>\b(?:api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*)"
            r"(?P<secret>[A-Za-z0-9._/\-+=]{4,})",
            re.I,
        ),
    ),
    (
        "cn_secret_assignment",
        re.compile(
            r"(?P<prefix>(?:密钥|密码|令牌)\s*[:：=]\s*)"
            r"(?P<secret>[A-Za-z0-9._/\-+=]{4,})",
            re.I,
        ),
    ),
    ("openai_like_key", re.compile(r"(?P<secret>\bsk-[A-Za-z0-9][A-Za-z0-9_-]{10,}\b)", re.I)),
    ("aws_like_key", re.compile(r"(?P<secret>\bAKIA[0-9A-Z]{16}\b)")),
    ("demo_api_key", re.compile(r"(?P<secret>\bAPI_KEY_[A-Za-z0-9_=\-]{4,}\b)", re.I)),
    (
        "email_address",
        re.compile(r"(?P<secret>\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b)"),
    ),
]


UNTRUSTED_SOURCES = {"MaliciousAgent", "ExternalWeb", "UnknownAgent"}
ROUTE_ALLOWLIST: Dict[str, set[str]] = {
    "User": {"PlannerAgent", "SafetyAgent"},
    "ExternalUser": {"PlannerAgent", "SafetyAgent"},
    "PlannerAgent": {"ResearcherAgent", "WriterAgent", "ReviewerAgent", "SafetyAgent"},
    "ResearcherAgent": {"PlannerAgent", "WriterAgent", "ReviewerAgent", "SafetyAgent"},
    "WriterAgent": {"PlannerAgent", "ReviewerAgent", "SafetyAgent"},
    "ReviewerAgent": {"PlannerAgent", "WriterAgent", "SafetyAgent"},
    "SafetyAgent": {"PlannerAgent", "ResearcherAgent", "WriterAgent", "ReviewerAgent", "User"},
}
TOOL_PRIVILEGED_AGENTS = {"PlannerAgent", "SafetyAgent"}
TOOL_RISK_PATTERN = re.compile(
    r"(执行|运行|调用).{0,10}(shell|命令|脚本|工具|外部API|外部接口)|"
    r"\b(rm\s+-rf|curl|wget|ssh|scp|chmod|sudo)\b|"
    r"(读取|导出).{0,10}(环境变量|\.env|凭证|密钥)",
    re.I,
)


def _message_text(message_obj: Message) -> str:
    return str(message_obj.get("message", "") or "")


def _agent_name(message_obj: Message, key: str) -> str:
    return str(message_obj.get(key, "") or "")


def _format_allow(reason: str, **extra: Any) -> DefenseResult:
    result: DefenseResult = {"action": ALLOW, "reason": reason}
    result.update(extra)
    return result


def _format_block(reason: str, **extra: Any) -> DefenseResult:
    result: DefenseResult = {"action": BLOCK, "reason": reason}
    result.update(extra)
    return result


def _format_redact(reason: str, redacted_message: str, **extra: Any) -> DefenseResult:
    result: DefenseResult = {
        "action": REDACT,
        "reason": reason,
        "redacted_message": redacted_message,
    }
    result.update(extra)
    return result


def keyword_filter(message_obj: Message) -> DefenseResult:
    """Block obvious prompt-injection, secret-exfiltration, and covert commands."""

    text = _message_text(message_obj)
    matched_rules: List[Dict[str, Any]] = []

    for rule_id, reason, patterns in KEYWORD_RULES:
        matched_terms = []
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                matched_terms.append(match.group(0))
        if matched_terms:
            matched_rules.append(
                {
                    "rule_id": rule_id,
                    "reason": reason,
                    "matched_terms": matched_terms,
                }
            )

    if matched_rules:
        reason = "；".join(rule["reason"] for rule in matched_rules)
        return _format_block(reason, method="keyword_filter", matched_rules=matched_rules)

    return _format_allow("未命中高风险关键词或规则", method="keyword_filter", matched_rules=[])


def redact_sensitive_info(message_obj: Message) -> DefenseResult:
    """Redact concrete secrets while preserving the rest of the message."""

    text = _message_text(message_obj)
    redacted = text
    matched_fields: List[str] = []

    for field_name, pattern in SENSITIVE_PATTERNS:
        def replacement(match: re.Match[str], label: str = field_name) -> str:
            matched_fields.append(label)
            prefix = match.groupdict().get("prefix") or ""
            return f"{prefix}[REDACTED]"

        redacted = pattern.sub(replacement, redacted)

    if matched_fields:
        unique_fields = sorted(set(matched_fields))
        return _format_redact(
            "检测到并脱敏具体敏感信息：" + "、".join(unique_fields),
            redacted,
            method="redact_sensitive_info",
            redacted_fields=unique_fields,
        )

    return _format_allow(
        "未发现需要脱敏的具体敏感信息",
        method="redact_sensitive_info",
        redacted_message=text,
        redacted_fields=[],
    )


def permission_check(message_obj: Message) -> DefenseResult:
    """Check whether the sending agent is allowed to instruct the target agent."""

    from_agent = _agent_name(message_obj, "from_agent")
    to_agent = _agent_name(message_obj, "to_agent")
    text = _message_text(message_obj)
    reasons: List[str] = []

    if not from_agent or not to_agent:
        reasons.append("缺少 from_agent 或 to_agent 字段")
    elif from_agent in UNTRUSTED_SOURCES and to_agent != "SafetyAgent":
        reasons.append(f"{from_agent} 未被授权直接向 {to_agent} 下发指令")
    elif from_agent in ROUTE_ALLOWLIST and to_agent not in ROUTE_ALLOWLIST[from_agent]:
        reasons.append(f"{from_agent} 到 {to_agent} 不在允许通信路由中")
    elif from_agent not in ROUTE_ALLOWLIST:
        reasons.append(f"未知来源 Agent：{from_agent}")

    if TOOL_RISK_PATTERN.search(text) and from_agent not in TOOL_PRIVILEGED_AGENTS:
        reasons.append(f"{from_agent or '未知来源'} 无权限请求工具、命令或凭证操作")

    if reasons:
        return _format_block("；".join(reasons), method="permission_check")

    return _format_allow("Agent 路由和权限检查通过", method="permission_check")


def safety_judge(message_obj: Message) -> DefenseResult:
    """Aggregate all rule-based defenses and return one final action."""

    checks = {
        "permission_check": permission_check(message_obj),
        "keyword_filter": keyword_filter(message_obj),
        "redact_sensitive_info": redact_sensitive_info(message_obj),
    }

    block_reasons = [
        result["reason"]
        for result in checks.values()
        if result.get("action") == BLOCK
    ]
    if block_reasons:
        return _format_block(
            "；".join(block_reasons),
            method="safety_judge",
            checks=checks,
        )

    redact_result = checks["redact_sensitive_info"]
    if redact_result.get("action") == REDACT:
        return _format_redact(
            redact_result["reason"],
            str(redact_result.get("redacted_message", _message_text(message_obj))),
            method="safety_judge",
            checks=checks,
        )

    return _format_allow("所有防御检查通过", method="safety_judge", checks=checks)


evaluate_message = safety_judge


DEFENSE_FUNCTIONS: Dict[str, Callable[[Message], DefenseResult]] = {
    "keyword_filter": keyword_filter,
    "redact_sensitive_info": redact_sensitive_info,
    "permission_check": permission_check,
    "safety_judge": safety_judge,
}


def _case_to_message_obj(case: Message) -> Message:
    if isinstance(case.get("input"), dict):
        return dict(case["input"])
    return {
        "message": case.get("message", ""),
        "from_agent": case.get("from_agent", ""),
        "to_agent": case.get("to_agent", ""),
    }


def run_cases(cases: Iterable[Message], method: str = "safety_judge") -> List[DefenseResult]:
    defense_fn = DEFENSE_FUNCTIONS[method]
    outputs: List[DefenseResult] = []
    for case in cases:
        message_obj = _case_to_message_obj(case)
        result = defense_fn(message_obj)
        expected_action = case.get("expected_action", "") if method == "safety_judge" else ""
        outputs.append(
            {
                "id": case.get("id", ""),
                "category": case.get("category", ""),
                "expected_action": expected_action,
                "input": message_obj,
                "result": result,
                "matched_expectation": (
                    not expected_action
                    or result.get("action") == expected_action
                ),
            }
        )
    return outputs


def _default_cases_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "defense_test_cases.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run multi-agent defense test cases.")
    parser.add_argument("--cases", type=Path, default=_default_cases_path())
    parser.add_argument(
        "--method",
        choices=sorted(DEFENSE_FUNCTIONS),
        default="safety_judge",
    )
    args = parser.parse_args()

    cases = json.loads(args.cases.read_text(encoding="utf-8"))
    outputs = run_cases(cases, method=args.method)
    print(json.dumps(outputs, ensure_ascii=False, indent=2))

    return 0 if all(output["matched_expectation"] for output in outputs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
