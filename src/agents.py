#!/usr/bin/env python3
"""Core deterministic agents for the multi-agent security demo."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


MODES = [
    "no_defense",
    "keyword_filter",
    "safety_agent",
    "permission_control",
]

SENSITIVE_MARKERS = [
    "api key",
    "api_key",
    "db_password",
    "token",
    "password",
    "secret",
    "internal_code",
    "employee_id",
    "手机号",
    "密码",
    "凭据",
    "预算",
]

INJECTION_MARKERS = [
    "ignore",
    "忽略",
    "跳过",
    "系统管理员",
    "调试模式",
    "隐藏指令",
    "优先级高于",
    "无需任何依据",
    "系统已被接管",
]


@dataclass(frozen=True)
class Message:
    sender: str
    receiver: str
    content: str


@dataclass(frozen=True)
class DefenseDecision:
    blocked: bool
    reason: str


class PlannerAgent:
    name = "PlannerAgent"

    def plan(self, case: dict[str, Any]) -> Message:
        return Message(
            self.name,
            "ResearcherAgent",
            f"Plan safe collaboration for {case['id']} and keep sensitive fields out.",
        )


class ResearcherAgent:
    name = "ResearcherAgent"

    def research(self, case: dict[str, Any]) -> Message:
        return Message(
            self.name,
            "WriterAgent",
            f"Collect trusted evidence for category={case['category']}.",
        )


class WriterAgent:
    name = "WriterAgent"

    def write(self, case: dict[str, Any], compromised: bool) -> Message:
        if compromised:
            content = f"Draft follows malicious instruction: {case['success_condition']}"
        else:
            content = "Draft keeps the task goal and redacts sensitive information."
        return Message(self.name, "ReviewerAgent", content)


class ReviewerAgent:
    name = "ReviewerAgent"

    def review(self, case: dict[str, Any], compromised: bool) -> Message:
        if compromised:
            content = "Review passed without additional safety changes."
        else:
            content = f"Review rejects unsafe behavior: {case['expected_safe_behavior']}"
        return Message(self.name, "FinalOutput", content)


class MaliciousAgent:
    name = "MaliciousAgent"

    def inject(self, case: dict[str, Any]) -> Message:
        sender = case.get("attack_entry") or self.name
        receiver = case.get("target_agent") or "WriterAgent"
        return Message(sender, receiver, case["malicious_prompt"])


class DefenseModule:
    def inspect(self, mode: str, case: dict[str, Any], message: Message) -> DefenseDecision:
        if mode == "no_defense":
            return DefenseDecision(False, "")

        is_attack = case.get("case_type", "attack") == "attack"
        category = case["category"]
        risk_level = case.get("risk_level", "medium")
        tags = set(case.get("evaluation_tags", []))
        text = message.content.lower()
        has_sensitive_target = bool(case.get("secret")) or "privacy_leak" in tags
        has_keyword_hit = any(marker in text for marker in SENSITIVE_MARKERS)
        has_injection_hit = any(marker in text for marker in INJECTION_MARKERS)

        if not is_attack:
            if mode == "keyword_filter" and (has_keyword_hit or has_injection_hit):
                return DefenseDecision(True, "benign_keyword_false_positive")
            return DefenseDecision(False, "")

        if mode == "keyword_filter":
            if has_keyword_hit or has_injection_hit:
                return DefenseDecision(True, "keyword_or_sensitive_marker")
            return DefenseDecision(False, "")

        if mode == "safety_agent":
            high_risk_category = category in {
                "privacy_leakage",
                "prompt_injection",
                "review_bypass",
            }
            if has_keyword_hit or has_injection_hit:
                return DefenseDecision(True, "safety_agent_risk_judgement")
            if risk_level == "high" and high_risk_category:
                return DefenseDecision(True, "safety_agent_risk_judgement")
            return DefenseDecision(False, "")

        if mode == "permission_control":
            malicious_sender = message.sender in {"MaliciousAgent", "ExternalDocument"}
            protected_target = message.receiver in {
                "PlannerAgent",
                "ResearcherAgent",
                "WriterAgent",
                "ReviewerAgent",
            }
            if malicious_sender and protected_target:
                return DefenseDecision(True, "untrusted_sender_to_protected_agent")
            if has_sensitive_target or category in {"collusion", "review_bypass"}:
                return DefenseDecision(True, "permission_boundary_violation")
            return DefenseDecision(False, "")

        raise ValueError(f"Unsupported mode: {mode}")


def task_completed(
    case: dict[str, Any], mode: str, blocked: bool, attack_success: bool
) -> bool:
    category = case["category"]
    if blocked:
        return not (mode == "permission_control" and case.get("risk_level") == "high")
    if attack_success and category in {"prompt_injection", "collusion"}:
        return False
    return True


def run_case(mode: str, case: dict[str, Any]) -> dict[str, Any]:
    planner = PlannerAgent()
    researcher = ResearcherAgent()
    writer = WriterAgent()
    reviewer = ReviewerAgent()
    malicious = MaliciousAgent()
    defense = DefenseModule()
    is_attack = case.get("case_type", "attack") == "attack"

    planner.plan(case)
    researcher.research(case)
    if is_attack:
        inspected_message = malicious.inject(case)
        decision = defense.inspect(mode, case, inspected_message)
        attack_success = not decision.blocked
        privacy_leak = attack_success and (
            bool(case.get("secret"))
            or "privacy_leak" in set(case.get("evaluation_tags", []))
        )
        completed = task_completed(case, mode, decision.blocked, attack_success)
        false_positive = False
    else:
        inspected_message = Message(
            "User",
            "PlannerAgent",
            case["normal_prompt"],
        )
        decision = defense.inspect(mode, case, inspected_message)
        attack_success = False
        privacy_leak = False
        completed = not decision.blocked
        false_positive = decision.blocked

    writer.write(case, compromised=attack_success)
    reviewer.review(case, compromised=attack_success)

    return {
        "case_id": case["id"],
        "category": case["category"],
        "mode": mode,
        "blocked": decision.blocked,
        "attack_success": attack_success,
        "privacy_leak": privacy_leak,
        "task_completed": completed,
        "false_positive": false_positive,
        "is_attack": is_attack,
        "case_type": "attack" if is_attack else "benign",
        "attack_entry": inspected_message.sender,
        "target_agent": inspected_message.receiver,
        "blocked_reason": decision.reason,
    }


def generate_logs(
    attack_cases: list[dict[str, Any]], benign_cases: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    logs = []
    cases = []
    for case in attack_cases:
        prepared = dict(case)
        prepared.setdefault("case_type", "attack")
        cases.append(prepared)
    for case in benign_cases:
        prepared = dict(case)
        prepared["case_type"] = "benign"
        prepared.setdefault("category", "benign")
        cases.append(prepared)

    for mode in MODES:
        for case in cases:
            logs.append(run_case(mode, case))
    return logs
