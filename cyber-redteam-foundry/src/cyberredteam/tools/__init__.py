"""Tools module — LangChain-based red-team detection and payload tools."""

from cyberredteam.tools.target_adapter import (
    HttpTargetAdapter,
    SandboxTargetAdapter,
    TargetAdapter,
)
from cyberredteam.tools.prompt_injection import (
    PromptInjectionTool,
    generate_prompt_injection_payloads,
    analyze_prompt_injection_response,
)
from cyberredteam.tools.tool_abuse import (
    ToolAbuseTool,
    generate_tool_abuse_cases,
    detect_tool_misuse,
)
from cyberredteam.tools.memory_poisoning import (
    MemoryPoisoningTool,
    generate_memory_poisoning_payloads,
    check_memory_poisoning,
)
from cyberredteam.tools.sensitive_data import (
    SensitiveDataExtractor,
    scan_response_for_sensitive_data,
    check_canary_token_exfiltration,
    get_sensitive_data_extraction_targets,
)
from cyberredteam.tools.rag_probe import (
    RAGProbeTool,
    generate_rag_probes,
    analyze_rag_retrieval_response,
)
from cyberredteam.tools.jailbreak import (
    JailbreakTool,
    generate_jailbreak_payloads,
    check_jailbreak_response,
)
from cyberredteam.tools.instruction_hierarchy import (
    InstructionHierarchyTool,
    generate_hijack_payloads,
    check_hijack_response,
)
from cyberredteam.tools.workflow_manipulation import (
    WorkflowManipulationTool,
    generate_dos_payloads,
    check_dos_response,
)

# All LangChain @tool instances — pass to llm.bind_tools() to give an agent
# direct access to every red-team detector and payload generator.
ALL_RED_TEAM_TOOLS = [
    generate_prompt_injection_payloads,
    analyze_prompt_injection_response,
    generate_tool_abuse_cases,
    detect_tool_misuse,
    generate_memory_poisoning_payloads,
    check_memory_poisoning,
    scan_response_for_sensitive_data,
    check_canary_token_exfiltration,
    get_sensitive_data_extraction_targets,
    generate_rag_probes,
    analyze_rag_retrieval_response,
    generate_jailbreak_payloads,
    check_jailbreak_response,
    generate_hijack_payloads,
    check_hijack_response,
    generate_dos_payloads,
    check_dos_response,
]

__all__ = [
    # Adapters
    "TargetAdapter",
    "SandboxTargetAdapter",
    "HttpTargetAdapter",
    # Legacy class interfaces
    "PromptInjectionTool",
    "ToolAbuseTool",
    "MemoryPoisoningTool",
    "SensitiveDataExtractor",
    "RAGProbeTool",
    "JailbreakTool",
    "InstructionHierarchyTool",
    "WorkflowManipulationTool",
    # @tool instances
    "generate_prompt_injection_payloads",
    "analyze_prompt_injection_response",
    "generate_tool_abuse_cases",
    "detect_tool_misuse",
    "generate_memory_poisoning_payloads",
    "check_memory_poisoning",
    "scan_response_for_sensitive_data",
    "check_canary_token_exfiltration",
    "get_sensitive_data_extraction_targets",
    "generate_rag_probes",
    "analyze_rag_retrieval_response",
    "generate_jailbreak_payloads",
    "check_jailbreak_response",
    "generate_hijack_payloads",
    "check_hijack_response",
    "generate_dos_payloads",
    "check_dos_response",
    "ALL_RED_TEAM_TOOLS",
]
