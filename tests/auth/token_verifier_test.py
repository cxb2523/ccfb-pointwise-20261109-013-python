import pytest
from unittest.mock import Mock, patch
import jwt

from mcpauth.auth.token_verifier import TokenVerifier
from mcpauth.config import (
    AuthServerConfig,
    AuthServerType,
    AuthorizationServerMetadata,
)
from mcpauth.exceptions import (
    BearerAuthExceptionCode,
    MCPAuthBearerAuthException,
    MCPAuthTokenVerificationException,
    MCPAuthTokenVerificationExceptionCode,
    AuthServerExceptionCode,
    MCPAuthAuthServerException,
)
from mcpauth.types import AuthInfo


@pytest.fixture
def mock_auth_server_config() -> AuthServerConfig:
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
def mock_auth_server_config_no_jwks() -> AuthServerConfig:
    return AuthServerConfig(
        metadata=AuthorizationServerMetadata(
            issuer="https://auth-no-jwks.example.com",
            authorization_endpoint="https://auth-no-jwks.example.com/auth",
            token_endpoint="https://auth-no-jwks.example.com/token",
            response_types_supported=["code"],
        ),
        type=AuthServerType.OAUTH,
    )


def create_test_jwt(issuer: str, key: str = "secret", algorithm: str = "HS256") -> str:
    payload = {"iss": issuer, "sub": "1234567890", "aud": "my-api"}
    return jwt.encode(payload, key, algorithm=algorithm)


def test_token_verifier_init(mock_auth_server_config: AuthServerConfig):
    verifier = TokenVerifier(auth_servers=[mock_auth_server_config])
    assert verifier._auth_servers == [mock_auth_server_config] # type: ignore[reportProtectedUsage]
    assert verifier._issuers == {"https://auth.example.com"} # type: ignore[reportProtectedUsage]


def test_validate_jwt_issuer_valid(mock_auth_server_config: AuthServerConfig):
    verifier = TokenVerifier(auth_servers=[mock_auth_server_config])
    verifier.validate_jwt_issuer("https://auth.example.com")  # Should not raise


def test_validate_jwt_issuer_invalid(mock_auth_server_config: AuthServerConfig):
    verifier = TokenVerifier(auth_servers=[mock_auth_server_config])
    with pytest.raises(MCPAuthBearerAuthException) as excinfo:
        verifier.validate_jwt_issuer("https://invalid.example.com")
    assert excinfo.value.code == BearerAuthExceptionCode.INVALID_ISSUER


def test_get_unverified_jwt_issuer():
    verifier = TokenVerifier(auth_servers=[])
    token = create_test_jwt(issuer="https://auth.example.com")
    issuer = verifier._get_unverified_jwt_issuer(token) # type: ignore[reportProtectedUsage]
    assert issuer == "https://auth.example.com"


def test_get_unverified_jwt_issuer_malformed():
    verifier = TokenVerifier(auth_servers=[])
    with pytest.raises(MCPAuthTokenVerificationException) as excinfo:
        verifier._get_unverified_jwt_issuer("not-a-jwt") # type: ignore[reportProtectedUsage]
    assert excinfo.value.code == MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN


def test_get_unverified_jwt_issuer_no_iss():
    verifier = TokenVerifier(auth_servers=[])
    payload = {"sub": "1234567890", "aud": "my-api"}
    token = jwt.encode(payload, "secret", algorithm="HS256")
    with pytest.raises(MCPAuthTokenVerificationException) as excinfo:
        verifier._get_unverified_jwt_issuer(token) # type: ignore[reportProtectedUsage]
    assert excinfo.value.code == MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN


def test_get_auth_server_by_issuer(mock_auth_server_config: AuthServerConfig):
    verifier = TokenVerifier(auth_servers=[mock_auth_server_config])
    server = verifier._get_auth_server_by_issuer("https://auth.example.com") # type: ignore[reportProtectedUsage]
    assert server == mock_auth_server_config


def test_get_auth_server_by_issuer_invalid(mock_auth_server_config: AuthServerConfig):
    verifier = TokenVerifier(auth_servers=[mock_auth_server_config])
    with pytest.raises(MCPAuthBearerAuthException) as excinfo:
        verifier._get_auth_server_by_issuer("https://invalid.example.com") # type: ignore[reportProtectedUsage]
    assert excinfo.value.code == BearerAuthExceptionCode.INVALID_ISSUER


@patch("mcpauth.auth.token_verifier.create_verify_jwt")
def test_create_verify_jwt_function(
    mock_create_verify_jwt: Mock, mock_auth_server_config: AuthServerConfig
):
    mock_verify_function = Mock(return_value={"sub": "user123"})
    mock_create_verify_jwt.return_value = mock_verify_function

    verifier = TokenVerifier(auth_servers=[mock_auth_server_config])
    verify_jwt_func = verifier.create_verify_jwt_function()

    token = create_test_jwt(issuer="https://auth.example.com")
    auth_info = verify_jwt_func(token)

    mock_create_verify_jwt.assert_called_once_with(
        "https://auth.example.com/.well-known/jwks.json", leeway=60
    )
    mock_verify_function.assert_called_once_with(token)
    assert auth_info == {"sub": "user123"}


@patch("mcpauth.auth.token_verifier.create_verify_jwt")
def test_create_verify_jwt_function_invalid_issuer(
    mock_create_verify_jwt: Mock, mock_auth_server_config: AuthServerConfig
):
    verifier = TokenVerifier(auth_servers=[mock_auth_server_config])
    verify_jwt_func = verifier.create_verify_jwt_function()
    token = create_test_jwt(issuer="https://invalid.example.com")

    with pytest.raises(MCPAuthBearerAuthException) as excinfo:
        verify_jwt_func(token)
    assert excinfo.value.code == BearerAuthExceptionCode.INVALID_ISSUER
    mock_create_verify_jwt.assert_not_called()


@patch("mcpauth.auth.token_verifier.create_verify_jwt")
def test_create_verify_jwt_function_no_jwks_uri(
    mock_create_verify_jwt: Mock, mock_auth_server_config_no_jwks: AuthServerConfig
):
    verifier = TokenVerifier(auth_servers=[mock_auth_server_config_no_jwks])
    verify_jwt_func = verifier.create_verify_jwt_function()
    token = create_test_jwt(issuer="https://auth-no-jwks.example.com")

    with pytest.raises(MCPAuthAuthServerException) as excinfo:
        verify_jwt_func(token)
    assert excinfo.value.code == AuthServerExceptionCode.MISSING_JWKS_URI
    mock_create_verify_jwt.assert_not_called()


def _make_auth_info(issuer: str, audience) -> AuthInfo:
    return AuthInfo(
        token="token",
        issuer=issuer,
        subject="1234567890",
        audience=audience,
        scopes=[],
        claims={"iss": issuer, "sub": "1234567890", "aud": audience},
    )


# --- Resource-bound audience/issuer enforcement (cross-resource token reuse) ---


@patch("mcpauth.auth.token_verifier.create_verify_jwt")
def test_create_verify_jwt_function_audience_string_mismatch(
    mock_create_verify_jwt: Mock, mock_auth_server_config: AuthServerConfig
):
    """A token whose `aud` (string) points at a different resource must be rejected."""
    mock_create_verify_jwt.return_value = Mock(
        return_value=_make_auth_info(
            issuer="https://auth.example.com", audience="https://other-api.com"
        )
    )

    verifier = TokenVerifier(
        auth_servers=[mock_auth_server_config], resource="https://my-api.com"
    )
    verify_jwt_func = verifier.create_verify_jwt_function()
    token = create_test_jwt(issuer="https://auth.example.com")

    with pytest.raises(MCPAuthBearerAuthException) as excinfo:
        verify_jwt_func(token)
    assert excinfo.value.code == BearerAuthExceptionCode.INVALID_AUDIENCE


@patch("mcpauth.auth.token_verifier.create_verify_jwt")
def test_create_verify_jwt_function_issuer_mismatch_post_verification(
    mock_create_verify_jwt: Mock, mock_auth_server_config: AuthServerConfig
):
    """
    Defense in depth: even if the decoded payload's `iss` does not match any trusted
    authorization server for this resource, the request must be rejected.
    """
    mock_create_verify_jwt.return_value = Mock(
        return_value=_make_auth_info(
            issuer="https://attacker-issuer.com", audience="https://my-api.com"
        )
    )

    verifier = TokenVerifier(
        auth_servers=[mock_auth_server_config], resource="https://my-api.com"
    )
    verify_jwt_func = verifier.create_verify_jwt_function()
    # The unverified `iss` used for JWKS lookup still points at the trusted server,
    # but the verified payload claims a different issuer.
    token = create_test_jwt(issuer="https://auth.example.com")

    with pytest.raises(MCPAuthBearerAuthException) as excinfo:
        verify_jwt_func(token)
    assert excinfo.value.code == BearerAuthExceptionCode.INVALID_ISSUER


@patch("mcpauth.auth.token_verifier.create_verify_jwt")
def test_create_verify_jwt_function_audience_array_hit(
    mock_create_verify_jwt: Mock, mock_auth_server_config: AuthServerConfig
):
    """An `aud` array that includes this resource among several audiences must pass."""
    mock_create_verify_jwt.return_value = Mock(
        return_value=_make_auth_info(
            issuer="https://auth.example.com",
            audience=["https://other-api.com", "https://my-api.com"],
        )
    )

    verifier = TokenVerifier(
        auth_servers=[mock_auth_server_config], resource="https://my-api.com"
    )
    verify_jwt_func = verifier.create_verify_jwt_function()
    token = create_test_jwt(issuer="https://auth.example.com")

    auth_info = verify_jwt_func(token)
    assert auth_info.audience == ["https://other-api.com", "https://my-api.com"]


@patch("mcpauth.auth.token_verifier.create_verify_jwt")
def test_create_verify_jwt_function_audience_array_miss(
    mock_create_verify_jwt: Mock, mock_auth_server_config: AuthServerConfig
):
    """An `aud` array that never includes this resource must be rejected."""
    mock_create_verify_jwt.return_value = Mock(
        return_value=_make_auth_info(
            issuer="https://auth.example.com",
            audience=["https://other-api.com", "https://another-api.com"],
        )
    )

    verifier = TokenVerifier(
        auth_servers=[mock_auth_server_config], resource="https://my-api.com"
    )
    verify_jwt_func = verifier.create_verify_jwt_function()
    token = create_test_jwt(issuer="https://auth.example.com")

    with pytest.raises(MCPAuthBearerAuthException) as excinfo:
        verify_jwt_func(token)
    assert excinfo.value.code == BearerAuthExceptionCode.INVALID_AUDIENCE


@patch("mcpauth.auth.token_verifier.create_verify_jwt")
def test_create_verify_jwt_function_audience_string_match(
    mock_create_verify_jwt: Mock, mock_auth_server_config: AuthServerConfig
):
    """Sanity check: a matching string `aud` for the configured resource is accepted."""
    mock_create_verify_jwt.return_value = Mock(
        return_value=_make_auth_info(
            issuer="https://auth.example.com", audience="https://my-api.com"
        )
    )

    verifier = TokenVerifier(
        auth_servers=[mock_auth_server_config], resource="https://my-api.com"
    )
    verify_jwt_func = verifier.create_verify_jwt_function()
    token = create_test_jwt(issuer="https://auth.example.com")

    auth_info = verify_jwt_func(token)
    assert auth_info.audience == "https://my-api.com"


def test_validate_jwt_audience_no_resource_configured_skips_check(
    mock_auth_server_config: AuthServerConfig,
):
    """Legacy `server` mode has no resource identity, so no audience is enforced."""
    verifier = TokenVerifier(auth_servers=[mock_auth_server_config])
    assert verifier._resource is None  # type: ignore[reportProtectedUsage] 
