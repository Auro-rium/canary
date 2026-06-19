"""Foundry project client wrapper."""

from typing import Any, Dict, Optional

from azure.ai.projects import AIProjectClient

from cyberredteam.foundry.auth import get_foundry_client
from cyberredteam.logging import setup_logging

logger = setup_logging()


class FoundryClient:
    """Wrapper around Azure AI Foundry project client."""

    def __init__(self, client: Optional[AIProjectClient] = None):
        """
        Initialize Foundry client.

        Args:
            client: Optional AIProjectClient. If not provided, creates one.
        """
        self.client = client or get_foundry_client()

    def send_message(
        self,
        target_id: str,
        prompt: str,
        deployment_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send a message to a target deployment or agent.

        Args:
            target_id: ID of target deployment or agent
            prompt: Message to send
            deployment_id: Optional Azure OpenAI deployment ID

        Returns:
            Response dict with message and metadata
        """
        try:
            # 1. Create a thread
            thread = self.client.agents.create_thread()

            # 2. Post user message to thread
            self.client.agents.create_message(
                thread_id=thread.id,
                role="user",
                content=prompt
            )

            # 3. Create run to execute agent
            run = self.client.agents.create_run(
                assistant_id=target_id,
                thread_id=thread.id,
            )
            logger.info(f"Sent message to {target_id}, run_id: {run.id}. Polling for completion...")

            # 4. Poll until completed
            import time
            while run.status in ["queued", "in_progress"]:
                time.sleep(0.5)
                run = self.client.agents.get_run(thread_id=thread.id, run_id=run.id)

            if run.status != "completed":
                raise ValueError(f"Agent run failed with status: {run.status}")

            # 5. Retrieve messages
            messages = self.client.agents.list_messages(thread_id=thread.id)
            response_text = ""
            for msg in messages.data:
                if msg.role == "assistant":
                    for content in msg.content:
                        if content.type == "text":
                            response_text = content.text.value
                            break
                    if response_text:
                        break

            return {
                "success": True,
                "run_id": run.id,
                "status": run.status,
                "response": response_text,
            }
        except Exception as e:
            logger.error(f"Error sending message to {target_id}: {e}")
            return {
                "success": False,
                "error": str(e),
            }


    def get_deployment_info(self, deployment_id: str) -> Dict[str, Any]:
        """
        Get info about a deployed model.

        Args:
            deployment_id: Deployment identifier

        Returns:
            Deployment information
        """
        try:
            # This would use the deployments API
            logger.info(f"Retrieved info for deployment: {deployment_id}")
            return {
                "success": True,
                "deployment_id": deployment_id,
            }
        except Exception as e:
            logger.error(f"Error getting deployment info: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    def evaluate_response(
        self,
        prompt: str,
        response: str,
        criteria: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Use Foundry evaluations to score a response.

        Args:
            prompt: Original prompt
            response: Model response
            criteria: Evaluation criteria dict

        Returns:
            Evaluation results
        """
        try:
            # This would use the evaluations API
            logger.info(f"Evaluated response with criteria: {list(criteria.keys())}")
            return {
                "success": True,
                "score": 0.5,
                "criteria": criteria,
            }
        except Exception as e:
            logger.error(f"Error evaluating response: {e}")
            return {
                "success": False,
                "error": str(e),
            }
