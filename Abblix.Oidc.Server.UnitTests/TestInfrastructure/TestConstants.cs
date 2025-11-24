// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// Common constants used across OIDC Server unit tests.
/// Eliminates magic strings and provides consistent test data.
/// </summary>
public static class TestConstants
{
    /// <summary>
    /// Default test client ID used in most tests.
    /// </summary>
    public const string DefaultClientId = "test_client";

    /// <summary>
    /// Alternative client ID for multi-client scenarios.
    /// </summary>
    public const string AlternativeClientId = "another_client";

    /// <summary>
    /// Default test client secret.
    /// </summary>
    public const string DefaultClientSecret = "test_secret";

    /// <summary>
    /// Invalid client secret for negative testing.
    /// </summary>
    public const string InvalidClientSecret = "wrong_secret";

    /// <summary>
    /// Default redirect URI for authorization flows.
    /// </summary>
    public const string DefaultRedirectUri = "https://example.com/callback";

    /// <summary>
    /// Alternative redirect URI for multi-URI scenarios.
    /// </summary>
    public const string AlternativeRedirectUri = "https://example.com/callback2";

    /// <summary>
    /// Invalid redirect URI for negative testing.
    /// </summary>
    public const string InvalidRedirectUri = "https://evil.com/steal-tokens";

    /// <summary>
    /// Default scope value (OpenID Connect mandatory scope).
    /// </summary>
    public const string DefaultScope = "openid";

    /// <summary>
    /// Profile scope for user profile information.
    /// </summary>
    public const string ProfileScope = "profile";

    /// <summary>
    /// Email scope for user email information.
    /// </summary>
    public const string EmailScope = "email";

    /// <summary>
    /// Address scope for user address information.
    /// </summary>
    public const string AddressScope = "address";

    /// <summary>
    /// Phone scope for user phone information.
    /// </summary>
    public const string PhoneScope = "phone";

    /// <summary>
    /// Offline access scope for refresh tokens.
    /// </summary>
    public const string OfflineAccessScope = "offline_access";

    /// <summary>
    /// Default authorization code for token exchange.
    /// </summary>
    public const string DefaultAuthorizationCode = "test_auth_code_123";

    /// <summary>
    /// Default access token for testing.
    /// </summary>
    public const string DefaultAccessToken = "test_access_token_xyz";

    /// <summary>
    /// Default refresh token for testing.
    /// </summary>
    public const string DefaultRefreshToken = "test_refresh_token_abc";

    /// <summary>
    /// Default ID token for testing.
    /// </summary>
    public const string DefaultIdToken = "eyJ...test_id_token...";

    /// <summary>
    /// Default subject (user ID) for testing.
    /// </summary>
    public const string DefaultSubject = "user_12345";

    /// <summary>
    /// Default user code for device authorization flow.
    /// </summary>
    public const string DefaultUserCode = "ABCD-EFGH";

    /// <summary>
    /// Default device code for device authorization flow.
    /// </summary>
    public const string DefaultDeviceCode = "device_code_xyz123";

    /// <summary>
    /// Default request URI for PAR (Pushed Authorization Requests).
    /// </summary>
    public const string DefaultRequestUri = "urn:ietf:params:oauth:request_uri:abcdef123";

    /// <summary>
    /// Default state parameter for authorization requests.
    /// </summary>
    public const string DefaultState = "test_state_abc123";

    /// <summary>
    /// Default nonce parameter for OpenID Connect.
    /// </summary>
    public const string DefaultNonce = "test_nonce_xyz789";

    /// <summary>
    /// Default PKCE code verifier.
    /// </summary>
    public const string DefaultCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    /// <summary>
    /// Default PKCE code challenge (SHA-256 hash of code verifier).
    /// </summary>
    public const string DefaultCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    /// <summary>
    /// Default issuer URI for token generation.
    /// </summary>
    public const string DefaultIssuer = "https://auth.example.com";

    /// <summary>
    /// Default audience for token validation.
    /// </summary>
    public const string DefaultAudience = "https://api.example.com";

    /// <summary>
    /// Default username for resource owner password credentials flow.
    /// </summary>
    public const string DefaultUsername = "testuser";

    /// <summary>
    /// Default password for resource owner password credentials flow.
    /// </summary>
    public const string DefaultPassword = "testpassword";

    /// <summary>
    /// SHA-512 hash size in bytes.
    /// Used for client secret hashing.
    /// </summary>
    public const int Sha512HashSize = 64;

    /// <summary>
    /// SHA-256 hash size in bytes.
    /// Used for PKCE code challenge.
    /// </summary>
    public const int Sha256HashSize = 32;

    /// <summary>
    /// Default token lifetime for access tokens.
    /// </summary>
    public static readonly TimeSpan DefaultAccessTokenLifetime = TimeSpan.FromHours(1);

    /// <summary>
    /// Default token lifetime for refresh tokens.
    /// </summary>
    public static readonly TimeSpan DefaultRefreshTokenLifetime = TimeSpan.FromDays(30);

    /// <summary>
    /// Default token lifetime for authorization codes.
    /// </summary>
    public static readonly TimeSpan DefaultAuthorizationCodeLifetime = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Default token lifetime for ID tokens.
    /// </summary>
    public static readonly TimeSpan DefaultIdTokenLifetime = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Default timeout for async operations in tests.
    /// </summary>
    public static readonly TimeSpan DefaultTestTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Short delay for testing expiration scenarios.
    /// Prefer using TimeProvider mocking instead of actual delays.
    /// </summary>
    public static readonly TimeSpan ShortDelay = TimeSpan.FromMilliseconds(100);
}
