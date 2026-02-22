"""Basic tests for dotenvage Python bindings."""

import dotenvage


def test_module_has_expected_exports():
    """Test that the module exports expected classes and functions."""
    assert hasattr(dotenvage, "SecretManager")
    assert hasattr(dotenvage, "EnvLoader")
    assert hasattr(dotenvage, "should_encrypt")


def test_should_encrypt_detects_sensitive_keys():
    """Test that should_encrypt detects sensitive key patterns."""
    # Keys that should be encrypted
    assert dotenvage.should_encrypt("API_KEY") is True
    assert dotenvage.should_encrypt("SECRET_TOKEN") is True
    assert dotenvage.should_encrypt("DATABASE_PASSWORD") is True
    assert dotenvage.should_encrypt("DB_PASSPHRASE") is True
    assert dotenvage.should_encrypt("PRIVATE_KEY") is True
    assert dotenvage.should_encrypt("AUTH_SECRET") is True

    # Keys that should NOT be encrypted
    assert dotenvage.should_encrypt("DATABASE_URL") is False
    assert dotenvage.should_encrypt("APP_NAME") is False
    assert dotenvage.should_encrypt("DEBUG") is False
    assert dotenvage.should_encrypt("PORT") is False
