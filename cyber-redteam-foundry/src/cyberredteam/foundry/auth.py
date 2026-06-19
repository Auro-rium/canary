"""Azure AI Foundry authentication and client initialization."""


from azure.ai.projects import AIProjectClient
from azure.identity import (
    ClientSecretCredential,
    DefaultAzureCredential,
)

from cyberredteam.logging import setup_logging
from cyberredteam.settings import get_settings

logger = setup_logging()


def get_credential():
    """
    Get Azure credential using configured method.

    Returns:
        Credential object for Azure authentication
    """
    settings = get_settings()

    if settings.azure_use_default_credential:
        logger.info("Using DefaultAzureCredential")
        return DefaultAzureCredential()

    if (
        settings.azure_tenant_id
        and settings.azure_client_id
        and settings.azure_client_secret
    ):
        logger.info("Using ClientSecretCredential")
        return ClientSecretCredential(
            tenant_id=settings.azure_tenant_id,
            client_id=settings.azure_client_id,
            client_secret=settings.azure_client_secret,
        )

    raise ValueError(
        "No Azure credentials configured. Set AZURE_USE_DEFAULT_CREDENTIAL or "
        "AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET"
    )


def get_foundry_client() -> AIProjectClient:
    """
    Get initialized Foundry project client.

    Returns:
        AIProjectClient connected to the configured project

    Raises:
        ValueError: If project connection string is not configured
    """
    settings = get_settings()

    if not settings.azure_project_connection_string:
        raise ValueError(
            "AZURE_PROJECT_CONNECTION_STRING not configured. "
            "Configure it in .env or set it as environment variable."
        )

    credential = get_credential()
    conn_str = settings.azure_project_connection_string

    try:
        if conn_str.startswith("http://") or conn_str.startswith("https://"):
            client = AIProjectClient(
                endpoint=conn_str,
                credential=credential,
            )
        else:
            if hasattr(AIProjectClient, "from_connection_string"):
                client = AIProjectClient.from_connection_string(
                    conn_str=conn_str,
                    credential=credential,
                )
            else:
                client = AIProjectClient(
                    endpoint=conn_str,
                    credential=credential,
                )
    except Exception as e:
        logger.error(f"Failed to initialize AIProjectClient: {e}")
        raise e

    logger.info(
        f"Initialized Foundry client for project: "
        f"{settings.azure_project_name or 'unknown'}"
    )
    return client

