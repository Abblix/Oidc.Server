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
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

namespace Abblix.Oidc.Server;

/// <summary>
/// Named EventId constants for every <c>[LoggerMessage]</c> in this assembly,
/// grouped into nested static classes per feature area. Refer to events as
/// <c>LogEvents.Endpoints.SomeEvent</c>, <c>LogEvents.ClientAuth.SomeEvent</c>,
/// etc., from the attribute. See <c>LOGGING.md</c> at the repository root for
/// the canonical range allocation and authoring rules.
/// </summary>
internal static class LogEvents
{
    /// <summary>
    /// Range 2000–2099: <c>Endpoints/Authorization</c>, <c>Endpoints/Token</c>,
    /// response builders. Each source class lives in its own nested static class
    /// with a packed sub-range inside the feature window.
    /// </summary>
    public static class Endpoints
    {
        /// <summary>
        /// <c>Endpoints/Token/Grants/JwtBearerGrantHandler.cs</c> — RFC 7523
        /// JWT Bearer grant validation pipeline (sub-range 2000–2019).
        /// </summary>
        public static class JwtBearer
        {
            private const int Base = 2000;

            public const int MissingAssertion = Base + 1;
            public const int AssertionTooLarge = Base + 2;
            public const int ValidationFailed = Base + 3;
            public const int MissingSubject = Base + 4;
            public const int AlgorithmNotAllowed = Base + 5;
            public const int TokenTypeNotAllowed = Base + 6;
            public const int MissingIssuedAt = Base + 7;
            public const int TooOld = Base + 8;
            public const int MissingJti = Base + 9;
            public const int ReplayDetected = Base + 10;
            public const int ScopesNotAllowed = Base + 11;
            public const int GrantSucceeded = Base + 12;
            public const int IssuerNotTrusted = Base + 13;
            public const int AudienceFailedStrict = Base + 14;
            public const int AudienceFailedPermissive = Base + 15;
        }
    }

    /// <summary>
    /// Range 3000–3099: <c>Features/ClientAuthentication</c>.
    /// </summary>
    public static class ClientAuth
    {
        /// <summary>
        /// <c>Features/ClientAuthentication/JwtAssertionAuthenticatorBase.cs</c> — shared
        /// JWT assertion validation pipeline for private_key_jwt and client_secret_jwt
        /// (sub-range 3000–3019).
        /// </summary>
        public static class JwtAssertionAuthenticatorBase
        {
            private const int Base = 3000;

            public const int WrongAssertionType = Base + 1;
            public const int MissingAssertion = Base + 2;
            public const int JwtValidationError = Base + 3;
            public const int AuthMethodNotAllowed = Base + 4;
            public const int SubjectExtractionFailed = Base + 5;
            public const int IssuerSubjectMismatch = Base + 6;
        }

        /// <summary>
        /// <c>Features/ClientAuthentication/ClientSecretAuthenticator.cs</c> — base
        /// authenticator for client_secret_basic and client_secret_post
        /// (sub-range 3020–3039).
        /// </summary>
        public static class ClientSecretAuthenticator
        {
            private const int Base = 3020;

            public const int ClientNotFound = Base + 1;
            public const int WrongAuthMethod = Base + 2;
            public const int NoSecretsConfigured = Base + 3;
            public const int NoMatchingSecret = Base + 4;
            public const int SecretExpired = Base + 5;
            public const int Authenticated = Base + 6;
        }

        /// <summary>
        /// <c>Features/ClientAuthentication/ClientSecretJwtAuthenticator.cs</c> —
        /// client_secret_jwt authentication via HMAC-signed JWT assertions
        /// (sub-range 3040–3059).
        /// </summary>
        public static class ClientSecretJwtAuthenticator
        {
            private const int Base = 3040;

            public const int AudienceValidationFailed = Base + 1;
            public const int WrongAuthMethod = Base + 2;
            public const int NoSecretsConfigured = Base + 3;
            public const int SecretWithoutRawValue = Base + 4;
        }

        /// <summary>
        /// <c>Features/ClientAuthentication/NoneClientAuthenticator.cs</c> — public
        /// clients that do not use client authentication (sub-range 3060–3069).
        /// </summary>
        public static class NoneClientAuthenticator
        {
            private const int Base = 3060;

            public const int ClientNotFound = Base + 1;
        }

        /// <summary>
        /// <c>Features/ClientAuthentication/TlsClientAuthenticator.cs</c> — RFC 8705
        /// self_signed_tls_client_auth (sub-range 3070–3084).
        /// </summary>
        public static class TlsClientAuthenticator
        {
            private const int Base = 3070;

            public const int ClientNotFound = Base + 1;
            public const int NoMatchingPublicKey = Base + 2;
            public const int Authenticated = Base + 3;
        }

        /// <summary>
        /// <c>Features/ClientAuthentication/TlsMetadataClientAuthenticator.cs</c> —
        /// RFC 8705 tls_client_auth via Subject DN / SAN matching
        /// (sub-range 3085–3099).
        /// </summary>
        public static class TlsMetadataClientAuthenticator
        {
            private const int Base = 3085;

            public const int NoTlsMetadataConfigured = Base + 1;
            public const int Authenticated = Base + 2;
        }
    }

    /// <summary>
    /// Range 4000–4099: <c>Endpoints/DynamicClientManagement</c>.
    /// </summary>
    public static class Dcr
    {
        private const int Base = 4000;
    }

    /// <summary>
    /// Range 5000–5099: <c>Features/Tokens</c> — validation, issuance, revocation.
    /// </summary>
    public static class Tokens
    {
        private const int Base = 5000;
    }

    /// <summary>
    /// Range 6000–6099: <c>Features/SecureHttpFetch</c>.
    /// </summary>
    public static class HttpFetch
    {
        private const int Base = 6000;
    }

    /// <summary>
    /// Range 7000–7099: <c>Features/DeviceAuthorization</c>,
    /// <c>Features/BackChannelAuthentication</c>.
    /// </summary>
    public static class Device
    {
        private const int Base = 7000;
    }

    /// <summary>
    /// Range 8000–8099: <c>Features/Licensing</c>.
    /// </summary>
    public static class Licensing
    {
        private const int Base = 8000;
    }

    /// <summary>
    /// Range 9000–9099: misc — Discovery, Storage, Issuer, Session, RandomGenerator.
    /// </summary>
    public static class Misc
    {
        private const int Base = 9000;
    }
}
