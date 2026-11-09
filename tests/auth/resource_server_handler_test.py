import jwt
import pytest
from unittest.mock import patch, Mock
from starlette.testclient import TestClient

from mcpauth.auth.resource_server_handler import (
    ResourceServerHandler,
    ResourceServerModeConfig,
)
from mcpauth.config import AuthServerConfig, AuthServerType, AuthorizationServerMetadata
from mcpauth.types import AuthInfo, ResourceServerConfig as RSC, ResourceServerMetadata
from mcpauth.exceptions import (
    MCPAuthAuthServerException,
    AuthServerExceptionCode,
    MCPAuthBearerAuthException,
    BearerAuthExceptionCode,
)
from mcpauth.utils import create_resource_metadata_endpoint


@pytest.fixture
def mock_auth_server() -> AuthServerConfig:
    return AuthServerConfig(
        metadata=AuthorizationServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/auth",
            token_endpoint="https://auth.example.com/token",
            response_types_supported=["code"],
        ),
        type=AuthServerType.OAUTH,
    )


@pytest.fixture
def mock_resource_config(mock_auth_server: AuthServerConfig) -> RSC:
    return RSC(
        metadata=ResourceServerMetadata(
            resource="https://my-api.com", authorization_servers=[mock_auth_server]
        )
    )


@pytest.fixture
def mock_auth_server_with_jwks() -> AuthServerConfig:
    return AuthServerConfig(
        metadata=AuthorizationServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/auth",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/.well-known/jwks.json",
            response_types_supported=["code"],
        ),
        type=AuthServerType.OAUTH,
    )


@pytest.fixture
def mock_resource_config_with_jwks(mock_auth_server_with_jwks: AuthServerConfig) -> RSC:
    return RSC(
        metadata=ResourceServerMetadata(
            resource="https://my-api.com",
            authorization_servers=[mock_auth_server_with_jwks],
        )
    )


def _make_jwt(issuer: str) -> str:
    return jwt.encode(
        {"iss": issuer, "sub": "1234567890", "aud": "irrelevant-for-unverified-lookup"},
        "secret",
        algorithm="HS256",
    )


def _make_auth_info(issuer: str, audience) -> AuthInfo:
    return AuthInfo(
        token="token",
        issuer=issuer,
        subject="1234567890",
        audience=audience,
        scopes=[],
        claims={"iss": issuer, "sub": "1234567890", "aud": audience},
    )


@patch("mcpauth.auth.resource_server_handler.TokenVerifier")
@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_init_single_resource(
    mock_validate: Mock,
    mock_token_verifier: Mock,
    mock_resource_config: RSC,
    mock_auth_server: AuthServerConfig,
):
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config)
    )
    assert handler._resources_configs == [mock_resource_config] # type: ignore[reportProtectedUsage]
    mock_validate.assert_called_once_with(mock_auth_server)
    mock_token_verifier.assert_called_once_with(
        [mock_auth_server], resource="https://my-api.com"
    )


@patch("mcpauth.auth.resource_server_handler.TokenVerifier")
@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_init_multiple_resources(
    mock_validate: Mock,
    mock_token_verifier: Mock,
    mock_resource_config: RSC,
    mock_auth_server: AuthServerConfig,
):
    config2 = RSC(
        metadata=ResourceServerMetadata(
            resource="my-api-2", authorization_servers=[mock_auth_server]
        )
    )
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=[mock_resource_config, config2])
    )
    assert handler._resources_configs == [mock_resource_config, config2] # type: ignore[reportProtectedUsage]
    assert mock_validate.call_count == 2
    assert mock_token_verifier.call_count == 2


@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_init_duplicate_resource_id(mock_validate: Mock, mock_resource_config: RSC):
    with pytest.raises(MCPAuthAuthServerException) as excinfo:
        ResourceServerHandler(
            ResourceServerModeConfig(
                protected_resources=[mock_resource_config, mock_resource_config]
            )
        )
    assert excinfo.value.code == AuthServerExceptionCode.INVALID_SERVER_CONFIG


@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_init_duplicate_auth_server(
    mock_validate: Mock, mock_auth_server: AuthServerConfig
):
    """Test that ResourceServerHandler throws an error if an auth server is duplicated for a resource."""
    config_with_duplicate_auth_server = RSC(
        metadata=ResourceServerMetadata(
            resource="https://my-api.com",
            authorization_servers=[mock_auth_server, mock_auth_server],
        )
    )
    with pytest.raises(MCPAuthAuthServerException) as excinfo:
        ResourceServerHandler(
            ResourceServerModeConfig(
                protected_resources=[config_with_duplicate_auth_server]
            )
        )
    assert excinfo.value.code == AuthServerExceptionCode.INVALID_SERVER_CONFIG
    assert (
        excinfo.value.cause["error_description"]  # type: ignore[reportGeneralTypeIssues]
        == "The authorization server ('https://auth.example.com') for resource 'https://my-api.com' is duplicated."
    )


@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_get_token_verifier_success(mock_validate: Mock, mock_resource_config: RSC):
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config)
    )
    verifier = handler.get_token_verifier("https://my-api.com")
    assert verifier is not None


@pytest.mark.parametrize("resource", [None, ""])
@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_get_token_verifier_no_resource(
    mock_validate: Mock, mock_resource_config: RSC, resource: str
):
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config)
    )
    with pytest.raises(MCPAuthAuthServerException) as excinfo:
        handler.get_token_verifier(resource)  # type: ignore
    assert excinfo.value.code == AuthServerExceptionCode.INVALID_SERVER_CONFIG


@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_get_token_verifier_unknown_resource(
    mock_validate: Mock, mock_resource_config: RSC
):
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config)
    )
    with pytest.raises(MCPAuthAuthServerException) as excinfo:
        handler.get_token_verifier("unknown-api")
    assert excinfo.value.code == AuthServerExceptionCode.INVALID_SERVER_CONFIG


@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_create_metadata_route(mock_validate: Mock, mock_resource_config: RSC):
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config)
    )
    router = handler.create_metadata_route()
    client = TestClient(router)

    endpoint_path = create_resource_metadata_endpoint(mock_resource_config.metadata.resource)
    
    response = client.get(endpoint_path)
    assert response.status_code == 200
    assert response.json()["resource"] == "https://my-api.com"
    assert response.json()["authorization_servers"] == ["https://auth.example.com"]

    response = client.options(endpoint_path)
    assert response.status_code == 204


# --- Cross-resource token reuse: aud/iss must be bound to this resource server ---


@patch("mcpauth.auth.token_verifier.create_verify_jwt")
@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_bearer_token_rejected_when_audience_does_not_match_resource(
    mock_validate: Mock,
    mock_create_verify_jwt: Mock,
    mock_resource_config_with_jwks: RSC,
):
    """A token issued for a different resource (`aud` string) must not authenticate here."""
    mock_create_verify_jwt.return_value = Mock(
        return_value=_make_auth_info(
            issuer="https://auth.example.com", audience="https://other-api.com"
        )
    )
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config_with_jwks)
    )
    verify = handler.get_token_verifier(
        "https://my-api.com"
    ).create_verify_jwt_function()

    with pytest.raises(MCPAuthBearerAuthException) as excinfo:
        verify(_make_jwt("https://auth.example.com"))
    assert excinfo.value.code == BearerAuthExceptionCode.INVALID_AUDIENCE


@patch("mcpauth.auth.token_verifier.create_verify_jwt")
@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_bearer_token_rejected_when_issuer_does_not_match_trusted_server(
    mock_validate: Mock,
    mock_create_verify_jwt: Mock,
    mock_resource_config_with_jwks: RSC,
):
    """
    A token whose verified payload claims an issuer other than this resource's configured
    authorization server must not authenticate here, even if the `aud` matches.
    """
    mock_create_verify_jwt.return_value = Mock(
        return_value=_make_auth_info(
            issuer="https://attacker-issuer.com", audience="https://my-api.com"
        )
    )
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config_with_jwks)
    )
    verify = handler.get_token_verifier(
        "https://my-api.com"
    ).create_verify_jwt_function()

    with pytest.raises(MCPAuthBearerAuthException) as excinfo:
        verify(_make_jwt("https://auth.example.com"))
    assert excinfo.value.code == BearerAuthExceptionCode.INVALID_ISSUER


@patch("mcpauth.auth.token_verifier.create_verify_jwt")
@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_bearer_token_accepted_when_audience_array_contains_resource(
    mock_validate: Mock,
    mock_create_verify_jwt: Mock,
    mock_resource_config_with_jwks: RSC,
):
    """A legitimate multi-resource token (`aud` array including this resource) must pass."""
    mock_create_verify_jwt.return_value = Mock(
        return_value=_make_auth_info(
            issuer="https://auth.example.com",
            audience=["https://other-api.com", "https://my-api.com"],
        )
    )
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config_with_jwks)
    )
    verify = handler.get_token_verifier(
        "https://my-api.com"
    ).create_verify_jwt_function()

    auth_info = verify(_make_jwt("https://auth.example.com"))
    assert auth_info.audience == ["https://other-api.com", "https://my-api.com"]


@patch("mcpauth.auth.token_verifier.create_verify_jwt")
@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_bearer_token_rejected_when_audience_array_does_not_contain_resource(
    mock_validate: Mock,
    mock_create_verify_jwt: Mock,
    mock_resource_config_with_jwks: RSC,
):
    """An `aud` array for other resources, never including this one, must be rejected."""
    mock_create_verify_jwt.return_value = Mock(
        return_value=_make_auth_info(
            issuer="https://auth.example.com",
            audience=["https://other-api.com", "https://another-api.com"],
        )
    )
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config_with_jwks)
    )
    verify = handler.get_token_verifier(
        "https://my-api.com"
    ).create_verify_jwt_function()

    with pytest.raises(MCPAuthBearerAuthException) as excinfo:
        verify(_make_jwt("https://auth.example.com"))
    assert excinfo.value.code == BearerAuthExceptionCode.INVALID_AUDIENCE
