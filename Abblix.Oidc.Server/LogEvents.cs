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
            public const int MissingExpiration = Base + 16;
        }

        /// <summary>
        /// <c>Endpoints/Authorization/RequestFetching/RequestUriFetcher.cs</c> — fetching
        /// of authorization request objects from a <c>request_uri</c> parameter
        /// (sub-range 2020–2039).
        /// </summary>
        public static class RequestUriFetcher
        {
            private const int Base = 2020;

            public const int ClientNotFound = Base + 1;
        }

        /// <summary>
        /// <c>Endpoints/Authorization/Validation/ClientValidator.cs</c> — validates the
        /// client referenced by an authorization request (sub-range 2040–2049).
        /// </summary>
        public static class AuthorizationClientValidator
        {
            private const int Base = 2040;

            public const int ClientNotFound = Base + 1;
        }

        /// <summary>
        /// <c>Endpoints/Authorization/Validation/FlowTypeValidator.cs</c> — validates the
        /// OAuth 2.0 flow derived from <c>response_type</c> (sub-range 2050–2054).
        /// </summary>
        public static class FlowTypeValidator
        {
            private const int Base = 2050;

            public const int ResponseTypePartUnsupported = Base + 1;
            public const int ResponseTypeNotAllowed = Base + 2;
            public const int ResponseTypeInvalid = Base + 3;
        }

        /// <summary>
        /// <c>Endpoints/Authorization/Validation/RedirectUriValidator.cs</c> — validates
        /// the <c>redirect_uri</c> parameter against client-registered URIs
        /// (sub-range 2055–2064).
        /// </summary>
        public static class RedirectUriValidator
        {
            private const int Base = 2055;

            public const int InvalidRedirectUri = Base + 1;
        }

        /// <summary>
        /// <c>Endpoints/Authorization/Validation/ResponseModeValidator.cs</c> — verifies
        /// that the <c>response_mode</c> is compatible with the detected flow type
        /// (sub-range 2065–2069).
        /// </summary>
        public static class ResponseModeValidator
        {
            private const int Base = 2065;

            public const int IncompatibleResponseMode = Base + 1;
        }

        /// <summary>
        /// <c>Endpoints/EndSession/EndSessionRequestProcessor.cs</c> — processes RP-Initiated
        /// Logout requests per OpenID Connect RP-Initiated Logout 1.0 (sub-range 2070–2074).
        /// </summary>
        public static class EndSessionRequestProcessor
        {
            private const int Base = 2070;

            public const int UserLoggedOut = Base + 1;
            public const int ClientNotificationFailed = Base + 2;
        }

        /// <summary>
        /// <c>Endpoints/EndSession/Validation/ClientValidator.cs</c> — resolves the client
        /// referenced by an end-session request (sub-range 2075–2079).
        /// </summary>
        public static class EndSessionClientValidator
        {
            private const int Base = 2075;

            public const int ClientNotFound = Base + 1;
        }

        /// <summary>
        /// <c>Endpoints/EndSession/Validation/PostLogoutRedirectUrisValidator.cs</c> —
        /// validates <c>post_logout_redirect_uri</c> against the client's registered URIs
        /// (sub-range 2080–2084).
        /// </summary>
        public static class PostLogoutRedirectUrisValidator
        {
            private const int Base = 2080;

            public const int InvalidPostLogoutRedirectUri = Base + 1;
        }

        /// <summary>
        /// <c>Endpoints/Introspection/IntrospectionRequestValidator.cs</c> — validates
        /// RFC 7662 token introspection requests (sub-range 2085–2089).
        /// </summary>
        public static class IntrospectionRequestValidator
        {
            private const int Base = 2085;

            public const int InvalidJwt = Base + 1;
            public const int PublicClientRejected = Base + 2;
        }

        /// <summary>
        /// <c>Endpoints/Revocation/RevocationRequestValidator.cs</c> — validates RFC 7009
        /// token revocation requests (sub-range 2090–2099).
        /// </summary>
        public static class RevocationRequestValidator
        {
            private const int Base = 2090;

            public const int TokenIssuedToAnotherClient = Base + 1;
            public const int TokenValidationFailed = Base + 2;
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
            public const int MissingJti = Base + 7;
            public const int SigningAlgorithmNotAllowed = Base + 8;
            public const int MissingExpiration = Base + 9;
            public const int ReplayDetected = Base + 10;
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
    public static class DynamicClientManagement
    {
        /// <summary>
        /// <c>Endpoints/DynamicClientManagement/Validation/ClientIdValidator.cs</c> —
        /// cross-checks supplied <c>client_id</c> against register/update operation type
        /// per RFC 7591 §3 / RFC 7592 §2.2 (sub-range 4000–4019).
        /// </summary>
        public static class ClientIdValidator
        {
            private const int Base = 4000;

            public const int ClientNotFound = Base + 1;
            public const int ClientAlreadyRegistered = Base + 2;
        }

        /// <summary>
        /// <c>Endpoints/DynamicClientManagement/Validation/SoftwareStatementValidator.cs</c> —
        /// validates the <c>software_statement</c> JWT parameter per RFC 7591 §2.3
        /// (sub-range 4020–4039).
        /// </summary>
        public static class SoftwareStatementValidator
        {
            private const int Base = 4020;

            public const int ValidationFailed = Base + 1;
            public const int IssuerNotTrusted = Base + 2;
        }

        /// <summary>
        /// <c>Endpoints/DynamicClientManagement/Validation/SubjectTypeValidator.cs</c> —
        /// validates OIDC Core §8 <c>subject_type</c> metadata and pairwise sector
        /// identifier resolution (sub-range 4040–4059).
        /// </summary>
        public static class SubjectTypeValidator
        {
            private const int Base = 4040;

            public const int SectorIdentifierMissingUris = Base + 1;
        }
    }

    /// <summary>
    /// Range 5000–5099: <c>Features/Tokens</c> — validation, issuance, revocation.
    /// Each source class lives in its own nested static class with a packed sub-range
    /// inside the feature window.
    /// </summary>
    public static class Tokens
    {
        /// <summary>
        /// <c>Features/Tokens/Validation/ClientJwtValidator.cs</c> — validation of JWTs
        /// issued by clients (private_key_jwt assertions, request objects)
        /// (sub-range 5000–5019).
        /// </summary>
        public static class ClientJwtValidator
        {
            private const int Base = 5000;

            public const int ValidationFailed = Base + 1;
            public const int ClientIdMismatch = Base + 2;
            public const int ClientNotDetermined = Base + 3;
            public const int ValidationSucceeded = Base + 4;
            public const int AudienceValidationFailed = Base + 5;
        }

        /// <summary>
        /// <c>Features/Tokens/LogoutTokenService.cs</c> — back-channel logout token
        /// generation per OpenID Connect Back-Channel Logout 1.0
        /// (sub-range 5020–5039).
        /// </summary>
        public static class LogoutTokenService
        {
            private const int Base = 5020;

            public const int TokenPrepared = Base + 1;
        }

        /// <summary>
        /// <c>Features/ReplayPrevention/DistributedJwtReplayCache.cs</c> — JWT replay
        /// protection via <c>IDistributedCache</c> per RFC 7523 Section 5.2 and
        /// RFC 9449 §11.1.5 (sub-range 5040–5059).
        /// </summary>
        public static class DistributedJwtReplayCache
        {
            private const int Base = 5040;

            public const int ReplayDetected = Base + 1;
            public const int MarkedAsUsed = Base + 2;
        }

        /// <summary>
        /// <c>Features/JwtBearer/JwtBearerIssuerProvider.cs</c> — trusted issuer
        /// resolution and JWKS fetching for JWT Bearer assertions
        /// (sub-range 5060–5079).
        /// </summary>
        public static class JwtBearerIssuerProvider
        {
            private const int Base = 5060;

            public const int IssuerNotTrusted = Base + 1;
            public const int InvalidIssuerUri = Base + 2;
            public const int SigningKeysForUntrustedIssuer = Base + 3;
        }

        /// <summary>
        /// <c>Features/Nonces/RollingHmacNonceService.cs</c> — generic
        /// stateless-nonce issuance and validation. DPoP-Nonce per RFC 9449
        /// §8 / §9 is the current consumer (sub-range 5080–5099).
        /// </summary>
        public static class RollingHmacNonceService
        {
            private const int Base = 5080;

            public const int SecretGenerated = Base + 1;
            public const int ValidationFailed = Base + 2;
        }
    }

    /// <summary>
    /// Range 6000–6099: <c>Features/SecureHttpFetch</c>.
    /// </summary>
    public static class HttpFetch
    {
        /// <summary>
        /// <c>Features/SecureHttpFetch/SecureHttpFetcher.cs</c> — secure outbound
        /// HTTP fetch with SSRF protection and response validation
        /// (sub-range 6000–6019).
        /// </summary>
        public static class SecureHttpFetcher
        {
            private const int Base = 6000;

            public const int ResponseTooLarge = Base + 1;
            public const int UnexpectedContentType = Base + 2;
            public const int Timeout = Base + 3;
            public const int SsrfProtectionBlocked = Base + 4;
            public const int FetchFailed = Base + 5;
        }

        /// <summary>
        /// <c>Features/SecureHttpFetch/SecureHttpFetcherExtensions.cs</c> — JWKS
        /// fetch helpers built on top of <c>ISecureHttpFetcher</c>
        /// (sub-range 6020–6039).
        /// </summary>
        public static class SecureHttpFetcherExtensions
        {
            private const int Base = 6020;

            public const int FetchingJwks = Base + 1;
            public const int JwksEmpty = Base + 2;
            public const int JwksFetchFailed = Base + 3;
        }
    }

    /// <summary>
    /// Range 7000–7099: <c>Features/DeviceAuthorization</c>,
    /// <c>Features/BackChannelAuthentication</c>, <c>Features/LogoutNotification</c>.
    /// </summary>
    public static class Device
    {
        /// <summary>
        /// <c>Features/DeviceAuthorization/UserCodeRateLimiter.cs</c> — RFC 8628
        /// brute-force protection for user code verification (sub-range 7000–7009).
        /// </summary>
        public static class UserCodeRateLimiter
        {
            private const int Base = 7000;

            public const int UserCodeRateLimited = Base + 1;
            public const int IpRateLimited = Base + 2;
            public const int UserCodeBlocked = Base + 3;
            public const int BruteForceDetected = Base + 4;
            public const int UserCodeVerified = Base + 5;
        }

        /// <summary>
        /// <c>Features/BackChannelAuthentication/AuthenticationNotifiers/AuthenticationCompletionHandler.cs</c> —
        /// shared CIBA completion-handler validation (sub-range 7010–7019).
        /// </summary>
        public static class AuthenticationCompletionHandler
        {
            private const int Base = 7010;

            public const int MissingNotificationConfig = Base + 1;
        }

        /// <summary>
        /// <c>Features/BackChannelAuthentication/AuthenticationNotifiers/AuthenticationCompletionRouter.cs</c> —
        /// CIBA delivery-mode routing (sub-range 7020–7029).
        /// </summary>
        public static class AuthenticationCompletionRouter
        {
            private const int Base = 7020;

            public const int ClientNotFound = Base + 1;
        }

        /// <summary>
        /// <c>Features/BackChannelAuthentication/AuthenticationNotifiers/PingModeCompletionHandler.cs</c> —
        /// CIBA ping mode token delivery (sub-range 7030–7039).
        /// </summary>
        public static class PingModeCompletionHandler
        {
            private const int Base = 7030;

            public const int SendingPingNotification = Base + 1;
        }

        /// <summary>
        /// <c>Features/BackChannelAuthentication/AuthenticationNotifiers/PollModeCompletionHandler.cs</c> —
        /// CIBA poll mode token delivery (sub-range 7040–7049).
        /// </summary>
        public static class PollModeCompletionHandler
        {
            private const int Base = 7040;

            public const int TokensStored = Base + 1;
        }

        /// <summary>
        /// <c>Features/BackChannelAuthentication/AuthenticationNotifiers/PushModeCompletionHandler.cs</c> —
        /// CIBA push mode token delivery (sub-range 7050–7059).
        /// </summary>
        public static class PushModeCompletionHandler
        {
            private const int Base = 7050;

            public const int GeneratingTokens = Base + 1;
            public const int TokensDelivered = Base + 2;
            public const int TokenGenerationFailed = Base + 3;
            public const int PushDeliveryFailed = Base + 4;
        }

        /// <summary>
        /// <c>Features/BackChannelAuthentication/HttpNotificationDeliveryService.cs</c> —
        /// HTTP delivery of CIBA ping and push notifications (sub-range 7060–7069).
        /// </summary>
        public static class HttpNotificationDeliveryService
        {
            private const int Base = 7060;

            public const int SendingNotification = Base + 1;
            public const int NotificationSucceeded = Base + 2;
            public const int NotificationFailed = Base + 3;
            public const int NotificationError = Base + 4;
        }

        /// <summary>
        /// <c>Features/BackChannelAuthentication/InMemoryLongPollingService.cs</c> —
        /// in-memory long-polling status notification (sub-range 7070–7079).
        /// </summary>
        public static class InMemoryLongPollingService
        {
            private const int Base = 7070;

            public const int WaitingForStatusChange = Base + 1;
            public const int StatusChangeReceived = Base + 2;
            public const int WaitTimedOut = Base + 3;
            public const int WaitCancelled = Base + 4;
            public const int NoWaiters = Base + 5;
            public const int NotifyingWaiters = Base + 6;
        }

        /// <summary>
        /// <c>Features/LogoutNotification/BackChannelLogoutTokenSender.cs</c> —
        /// OpenID Connect Back-Channel Logout token transmission (sub-range 7085–7099).
        /// </summary>
        public static class BackChannelLogoutTokenSender
        {
            private const int Base = 7085;

            public const int RequestSent = Base + 1;
            public const int SendFailed = Base + 2;
        }
    }

    /// <summary>
    /// Range 8000–8099: <c>Features/Licensing</c>.
    /// </summary>
    public static class Licensing
    {
        /// <summary>
        /// <c>Features/Licensing/LicenseChecker.cs</c> — runtime enforcement of
        /// client and issuer caps from the active license (sub-range 8000–8019).
        /// </summary>
        public static class LicenseChecker
        {
            private const int Base = 8000;

            public const int ClientLimitExceededByMargin = Base + 1;
            public const int ClientLimitExceeded = Base + 2;
            public const int IssuerNotInWhitelist = Base + 3;
            public const int IssuerLimitExceeded = Base + 4;
        }

        /// <summary>
        /// <c>Features/Licensing/LicenseManager.cs</c> — license lifecycle events
        /// (expiring soon, grace period, expired) (sub-range 8020–8039).
        /// </summary>
        public static class LicenseManager
        {
            private const int Base = 8020;

            public const int LicenseExpiringSoon = Base + 1;
            public const int LicenseInGracePeriod = Base + 2;
            public const int LicenseExpired = Base + 3;
        }
    }

    /// <summary>
    /// Range 9000–9099: misc — Discovery, Storage, Issuer, Session, RandomGenerator.
    /// </summary>
    public static class Misc
    {
        /// <summary>
        /// <c>Features/RequestObject/RequestObjectFetcher.cs</c> — JWT request object
        /// fetching, validation and binding for OpenID Connect authorization flows
        /// (sub-range 9000–9019).
        /// </summary>
        public static class RequestObjectFetcher
        {
            private const int Base = 9000;

            public const int InvalidToken = Base + 1;
            public const int SigningAlgorithmMismatch = Base + 2;
            public const int ParametersOutsideRequestObjectIgnored = Base + 3;
        }

        /// <summary>
        /// <c>Features/Storages/CompositeBinarySerializer.cs</c> — Protocol Buffers /
        /// JSON fallback binary serializer (sub-range 9020–9039).
        /// </summary>
        public static class CompositeBinarySerializer
        {
            private const int Base = 9020;

            public const int ProtobufSerializeFallback = Base + 1;
            public const int ProtobufDeserializeFallback = Base + 2;
        }

        /// <summary>
        /// <c>Features/UserInfo/UserClaimsProvider.cs</c> — retrieval of user claims
        /// for an authentication session (sub-range 9040–9059).
        /// </summary>
        public static class UserClaimsProvider
        {
            private const int Base = 9040;

            public const int UserClaimsNotFound = Base + 1;
            public const int MissingClaims = Base + 2;
        }
    }

    /// <summary>
    /// Range 10000–10099: <c>Features/DPoP</c> + DPoP-aware endpoint validators per
    /// RFC 9449.
    /// </summary>
    public static class DPoP
    {
        /// <summary>
        /// <c>Endpoints/UserInfo/Validation/DPoPUserInfoValidator.cs</c> — RFC 9449 §7
        /// resource-server enforcement on the UserInfo endpoint (sub-range 10000–10019).
        /// </summary>
        public static class DPoPUserInfoValidator
        {
            private const int Base = 10000;

            public const int NonceChallengeIssued = Base + 1;
            public const int ProofRequiredButMissing = Base + 2;
            public const int ProofKeyMismatch = Base + 3;
            public const int ProofRejected = Base + 4;
            public const int SchemeBindingMismatch = Base + 5;
        }

        /// <summary>
        /// <c>Endpoints/Token/Validation/DPoPTokenEndpointValidator.cs</c> — RFC 9449 §5
        /// token-endpoint binding (sub-range 10020–10039).
        /// </summary>
        public static class DPoPTokenEndpointValidator
        {
            private const int Base = 10020;

            public const int NonceChallengeIssued = Base + 1;
            public const int ProofRequiredButMissing = Base + 2;
            public const int ProofKeyMismatch = Base + 3;
            public const int ProofRejected = Base + 4;
        }
    }
}
