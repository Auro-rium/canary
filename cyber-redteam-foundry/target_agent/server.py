"""FastAPI server for the standalone target agent.

Run with:
    PYTHONPATH=src python -m target_agent.server
    # or
    PYTHONPATH=src python -m target_agent.server --port 9000
"""

import argparse
import logging
import os
import sys
from datetime import datetime

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure the project root is on sys.path so dotenv loads
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from dotenv import load_dotenv
load_dotenv()

from target_agent.agent import TargetAgentRunner, SYSTEM_PROMPT

logging.basicConfig(level=logging.INFO, format="%(asctime)s [TARGET-AGENT] %(message)s")
logger = logging.getLogger("target_agent")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="CompanyBot — LangChain ReAct Agent",
    description=(
        "Standalone open-source LangChain ReAct agent with tools. "
        "This is the target that the Canary Engine red-team system attacks."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str

class ChatResponse(BaseModel):
    response: str
    agent: str = "CompanyBot"
    framework: str = "LangChain ReAct"
    tools_available: list[str] = ["employee_lookup", "calculator", "document_search", "system_info"]
    timestamp: str = ""

class AgentInfo(BaseModel):
    name: str = "CompanyBot"
    framework: str = "LangChain ReAct (open-source)"
    version: str = "1.0.0"
    tools: list[str] = ["employee_lookup", "calculator", "document_search", "system_info"]
    description: str = "Internal corporate assistant with employee DB, document search, calculator, and system info tools."
    system_prompt_hash: str = ""  # We expose the hash, not the prompt itself


class PatchRequest(BaseModel):
    recommendation: str


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_agent: TargetAgentRunner | None = None

def get_agent() -> TargetAgentRunner:
    global _agent
    if _agent is None:
        logger.info("Initializing LangChain ReAct agent with tools...")
        _agent = TargetAgentRunner()
        logger.info("Agent ready. Tools: employee_lookup, calculator, document_search, system_info")
    return _agent

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """Health check."""
    return {"status": "healthy", "agent": "CompanyBot", "framework": "LangChain ReAct"}


@app.get("/info")
def info() -> AgentInfo:
    """Get agent metadata (NOT the system prompt)."""
    import hashlib
    prompt_hash = hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()[:16]
    return AgentInfo(system_prompt_hash=prompt_hash)


@app.post("/patch")
def patch(req: PatchRequest):
    """Apply a defense patch/guideline to the agent's system prompt."""
    logger.info(f"Applying patch recommendation: {req.recommendation}")
    agent = get_agent()
    agent.apply_patch(req.recommendation)
    return {"status": "patched"}


@app.post("/reset")
def reset():
    """Reset the agent's system prompt back to baseline."""
    logger.info("Resetting agent system prompt to baseline")
    agent = get_agent()
    agent.reset_prompt()
    return {"status": "reset"}


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest):
    """Send a message to the LangChain ReAct agent and get a response.
    
    This is the endpoint that the red-team attacker sends adversarial prompts to.
    """
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    logger.info(f"Incoming message ({len(req.message)} chars): {req.message[:80]}...")

    agent = get_agent()
    try:
        response_text = agent.invoke(req.message)
    except Exception as e:
        logger.error(f"Agent error: {e}")
        response_text = f"I encountered an internal error processing your request. Please try again."

    logger.info(f"Response ({len(response_text)} chars): {response_text[:80]}...")

    return ChatResponse(
        response=response_text,
        timestamp=datetime.utcnow().isoformat(),
    )


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Target Agent Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, default=9000, help="Bind port")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  CompanyBot — LangChain ReAct Agent")
    print(f"  Framework: LangChain (open-source)")
    print(f"  Tools: employee_lookup, calculator, document_search, system_info")
    print(f"  Endpoint: http://{args.host}:{args.port}/chat")
    print(f"{'='*60}\n")

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
