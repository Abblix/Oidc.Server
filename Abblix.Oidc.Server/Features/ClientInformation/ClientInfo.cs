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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Contains information about a client in an OAuth2/OpenID Connect context.
/// </summary>
/// <remarks>
/// This record encapsulates the details necessary to identify and configure the behavior of a client application
/// within an OAuth2 or OpenID Connect framework. It includes identifiers, secrets, and configuration options
/// that dictate how the client interacts with the authorization server and is authenticated or authorized during
/// the token issuance process.
/// </remarks>
public record ClientInfo(string ClientId)
{
    /// <summary>
    /// Identifies the client's unique identifier as recognized by the authorization server.
    /// It is used in various OAuth 2.0 and OpenID Connect flows to represent the client application.
    /// </summary>
    public string ClientId { get; set; } = ClientId;

    /// <summary>
    /// Classifies the client based on its ability to securely maintain a client secret. Derived from
    /// <see cref="TokenEndpointAuthMethod"/>: <c>none</c> yields <see cref="ClientType.Public"/>; any
    /// other authentication method (secrets, keys, certificates) yields <see cref="ClientType.Confidential"/>.
    /// </summary>
    public ClientType ClientType
        => ClientAuthenticationMethods.None.Equals(TokenEndpointAuthMethod, StringComparison.Ordinal)
            ? ClientType.Public
            : ClientType.Confidential;

    /// <summary>
    /// A collection of secrets associated with the client, used for authenticating the client to the authorization server.
    /// Multiple secrets can be provided for added security.
    /// </summary>
    public ClientSecret[]? ClientSecrets { get; set; }

    /// <summary>
    /// Specifies the URIs where the user-agent can be redirected after authorization.
    /// These URIs must be pre-registered and match the redirect URI provided in the authorization request.
    /// </summary>
    public Uri[] RedirectUris { get; set; } = [];

    /// <summary>
    /// Specifies the URIs where the user-agent can be redirected after logging out from the client application.
    /// This allows for a seamless user experience upon logout.
    /// </summary>
    public Uri[] PostLogoutRedirectUris { get; set; } = [];

    /// <summary>
    /// Indicates whether the client is to use Proof Key for Code Exchange (PKCE) in the authorization code flow,
    /// enhancing security for public clients.
    /// </summary>
    public bool? PkceRequired { get; set; } = true;

    /// <summary>
    /// Indicates if the client is allowed to use the "plain" method for PKCE.
    /// It is recommended to use stronger methods like "S256" for enhanced security.
    /// </summary>
    public bool PlainPkceAllowed { get; set; } = false;

    /// <summary>
    /// The validity period of an authorization code issued to this client.
    /// Shorter durations are recommended for higher security.
    /// </summary>
    public TimeSpan AuthorizationCodeExpiresIn { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Specifies the lifetime of access tokens issued to this client.
    /// Shorter access token lifetimes reduce the risk of token leakage.
    /// </summary>
    public TimeSpan AccessTokenExpiresIn { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Configures the behavior and properties of refresh tokens issued to this client,
    /// such as their expiration and renewal policies.
    /// </summary>
    public RefreshTokenOptions RefreshToken { get; set; } = new();

    /// <summary>
    /// Determines the validity period of identity tokens issued to this client.
    /// Shorter durations enhance security by reducing the window of misuse.
    /// </summary>
    public TimeSpan IdentityTokenExpiresIn { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Options for configuring front-channel logout behavior, allowing the client to participate in logout requests
    /// initiated by other clients.
    /// </summary>
    public FrontChannelLogoutOptions? FrontChannelLogout { get; set; }

    /// <summary>
    /// Options for configuring back-channel logout behavior, enabling the server to directly notify
    /// the client of logout events.
    /// </summary>
    public BackChannelLogoutOptions? BackChannelLogout { get; set; }

    /// <summary>
    /// Defines the response types that the client is permitted to use.
    /// This controls how tokens are issued in response to an authorization request.
    /// </summary>
    public string[][] AllowedResponseTypes { get; set; } = [[ResponseTypes.Code]];

    /// <summary>
    /// Specifies the grant types the client is authorized to use when obtaining tokens from the token endpoint.
    /// </summary>
    public string[] AllowedGrantTypes { get; set; } = [GrantTypes.AuthorizationCode];

    /// <summary>
    /// Allows the client to request tokens that enable access to the user's resources while they’re offline.
    /// </summary>
    public bool? OfflineAccessAllowed { get; set; } = false;

    /// <summary>
    /// The set of JSON Web Keys used by the client, typically for signing request objects and decrypting
    /// identity tokens or encrypted user information.
    /// </summary>
    public JsonWebKeySet? Jwks { get; set; }

    /// <summary>
    /// The publicly accessible URL where the client's JSON Web Key Set (JWKS) can be retrieved.
    /// </summary>
    public Uri? JwksUri { get; set; }

    /// <summary>
    /// Specifies the algorithm that must be used for signing identity token responses issued to this client.
    /// </summary>
    public string IdentityTokenSignedResponseAlgorithm { get; set; } = SigningAlgorithms.RS256;

    /// <summary>
    /// Controls whether claims about the authenticated user are included directly in the identity token
    /// instead of being obtained separately via the UserInfo endpoint.
    /// </summary>
    public bool ForceUserClaimsInIdentityToken { get; set; } = false;

    /// <summary>
    /// RFC 9396 §5.1: the client's per-client allowlist of authorization-detail <c>type</c>
    /// values it may use in <c>authorization_details</c> requests. DCR-exposed
    /// (<c>authorization_details_types</c>). Semantics:
    /// <list type="bullet">
    /// <item><description><c>null</c> — no per-client constraint; the client may use any
    /// <c>type</c> the server understands.</description></item>
    /// <item><description>Empty array — the client cannot use RAR; every
    /// <c>authorization_details</c> entry is rejected at request time regardless of
    /// <c>type</c>.</description></item>
    /// <item><description>Non-empty array — only the listed <c>type</c> values are accepted
    /// for this client; entries with other types are rejected with
    /// <c>invalid_authorization_details</c>.</description></item>
    /// </list>
    /// </summary>
    public string[]? AuthorizationDetailsTypes { get; set; }

    /// <summary>
    /// When <c>true</c>, the <c>authorization_details</c> claim is emitted on the ID token
    /// for this client in addition to the access token and introspection response. Default
    /// <c>false</c>. RFC 9396 is silent on id_token; default-off preserves role separation
    /// between identity assertion (id_token) and authorization payload (access token +
    /// introspection). Host-controlled behavioural extension — NOT exposed via DCR (no
    /// OIDC wire metadata for this), mirroring the
    /// <see cref="ForceUserClaimsInIdentityToken"/> precedent.
    /// </summary>
    public bool ForceAuthorizationDetailsInIdentityToken { get; set; } = false;

    /// <summary>
    /// RFC 8693 §2.1 per-client allowlist of <c>subject_token_type</c> URIs this client may submit
    /// to the Token Exchange grant. Independent of <see cref="AllowedGrantTypes"/> -- a client must
    /// have <c>urn:ietf:params:oauth:grant-type:token-exchange</c> in
    /// <see cref="AllowedGrantTypes"/> to invoke the grant, and the requested
    /// <c>subject_token_type</c> must additionally satisfy this allowlist.
    /// <list type="bullet">
    /// <item><description><c>null</c>: no constraint (any of <see cref="TokenExchangeTokenTypes"/> the
    /// AS can validate is accepted).</description></item>
    /// <item><description>Empty array: forbidden -- every Token Exchange request from this client is
    /// rejected with <c>invalid_request</c> regardless of <c>subject_token_type</c>.</description></item>
    /// <item><description>Non-empty array: allowlist -- only the listed type URIs are accepted; any other
    /// is rejected.</description></item>
    /// </list>
    /// Mirrors the <see cref="AuthorizationDetailsTypes"/> tri-state pattern.
    /// </summary>
    public string[]? TokenExchangeAllowedSubjectTokenTypes { get; set; }

    /// <summary>
    /// RFC 8693 §2.1 per-client allowlist of <c>audience</c> values this client may request when
    /// exchanging a token. The requested audience is written into the issued token's <c>aud</c>
    /// claim, so without a constraint a client could mint a token for any target service it names.
    /// This allowlist is therefore <b>default-deny</b>, unlike the unconstrained-by-default
    /// <see cref="TokenExchangeAllowedSubjectTokenTypes"/>:
    /// <list type="bullet">
    /// <item><description><c>null</c> or empty array: the client may not request any <c>audience</c>
    /// -- a Token Exchange request carrying one is rejected with <c>invalid_target</c>.</description></item>
    /// <item><description>Non-empty array: allowlist -- only the listed audience values are accepted;
    /// any other is rejected with <c>invalid_target</c>.</description></item>
    /// </list>
    /// A request that omits <c>audience</c> is unaffected.
    /// </summary>
    public string[]? TokenExchangeAllowedAudiences { get; set; }

    /// <summary>
    /// RFC 8693 §1.3: by default this AS rejects a Token Exchange request where the
    /// <c>subject_token</c> was originally issued to a different client than the one presenting
    /// it -- the "confused deputy" anti-pattern. When this client is intended to operate as an
    /// audit broker / proxy that legitimately receives tokens issued to other clients, set this
    /// to <c>true</c> to opt out of the default check. Has no effect when no subject_token
    /// origin can be determined.
    /// </summary>
    public bool AllowCrossClientSubjectTokenExchange { get; set; } = false;

    /// <summary>
    /// Describes how the client authenticates to the token endpoint per RFC 6749 §2.3 / OIDC Core §9.
    /// Common values include <c>client_secret_basic</c>, <c>client_secret_post</c>, <c>private_key_jwt</c>,
    /// <c>client_secret_jwt</c>, <c>tls_client_auth</c> (RFC 8705), and <c>none</c> (public clients).
    /// Drives the value of <see cref="ClientType"/>.
    /// </summary>
    public string TokenEndpointAuthMethod { get; set; } = ClientAuthenticationMethods.ClientSecretBasic;

    /// <summary>
    /// TLS client authentication metadata (RFC 8705) for tls_client_auth method.
    /// </summary>
    public TlsClientAuthOptions? TlsClientAuth { get; set; }

    /// <summary>
    /// RFC 9449 §5.2 client metadata (<c>dpop_bound_access_tokens</c>): when <c>true</c>,
    /// the client MUST present a valid DPoP proof on the token endpoint and the issued
    /// access token will be DPoP-bound (<c>cnf.jkt</c>). When <c>false</c>, DPoP is
    /// opportunistic — a valid proof still binds the token, otherwise a Bearer token is
    /// issued.
    /// </summary>
    public bool RequireDPoP { get; set; } = false;

    /// <summary>
    /// Determines the algorithm used for signing responses from the UserInfo endpoint.
    /// This can enhance the security of transmitted user information.
    /// </summary>
    public string UserInfoSignedResponseAlgorithm { get; set; } = SigningAlgorithms.None;

    /// <summary>
    /// A URL pointing to the client's policy documentation, providing transparency on how user data
    /// is handled and protected.
    /// </summary>
    public Uri? PolicyUri { get; set; }

    /// <summary>
    /// A URL pointing to the client's terms of service, outlining the legal agreement between the user
    /// and the service provider.
    /// </summary>
    public Uri? TermsOfServiceUri { get; set; }

    /// <summary>
    /// A URL pointing to an image file representing the client's logo, which can be displayed in user interfaces
    /// during authorization.
    /// </summary>
    public Uri? LogoUri { get; set; }

    /// <summary>
    /// A URI that allows third-party sites to initiate a login by the client, facilitating integrations and
    /// single sign-on scenarios.
    /// </summary>
    public Uri? InitiateLoginUri { get; set; }

    /// <summary>
    /// Specifies the subject identifier type requested by the client. This influences how the authorization server
    /// represents the authenticated user's identity to the client, affecting privacy and uniqueness across different
    /// clients. Common types include "public" and "pairwise".
    /// </summary>
    public string? SubjectType { get; set; } = SubjectTypes.Public;

    /// <summary>
    /// Used in conjunction with pairwise subject identifiers to calculate the subject value returned to the client.
    /// This field is particularly relevant to ensuring user privacy by providing a different subject identifier
    /// to each client, even if it's the same end-user. It typically contains a URL or a unique identifier
    /// representing the client's sector.
    /// </summary>
    public string? SectorIdentifier { get; set; }

    /// <summary>
    /// Indicates whether the login hint token should be parsed and validated as a JSON Web Token (JWT).
    /// </summary>
    /// <remarks>
    /// If this property is set to <c>false</c>, it means the login hint token is not in JWT format.
    /// In this case, the client is responsible for parsing and validating the token as part of the validation flow,
    /// as the authorization server will not handle its validation automatically.
    /// </remarks>
    public bool ParseLoginHintTokenAsJwt { get; set; } = true;

    /// <summary>
    /// The backchannel token delivery mode to be used by this client. This determines how tokens are delivered
    /// during backchannel authentication.
    /// </summary>
    public string? BackChannelTokenDeliveryMode { get; set; }

    /// <summary>
    /// The endpoint where backchannel client notifications are sent for this client.
    /// </summary>
    public Uri? BackChannelClientNotificationEndpoint { get; set; }

    /// <summary>
    /// The signing algorithm used for backchannel authentication requests sent to this client.
    /// </summary>
    public string? BackChannelAuthenticationRequestSigningAlg { get; set; }

    /// <summary>
    /// Indicates whether the backchannel authentication process supports user codes for this client.
    /// </summary>
    public bool BackChannelUserCodeParameter { get; set; } = false;

    /// <summary>
    /// The list of allowed URI values to validate the <c>request_uri</c> parameter in authorization requests.
    /// </summary>
    /// <remarks>
    /// The <c>request_uri</c> parameter references a pre-hosted authorization request object.
    /// This property specifies the valid URIs that can be included in the <c>request_uri</c> parameter.
    /// By defining this list, the server ensures that only pre-approved and secure URIs are accepted,
    /// mitigating risks such as unauthorized or malicious requests.
    /// </remarks>
    public Uri[] RequestUris { get; set; } = [];

    /// <summary>
    /// Describes the type of application represented by the client, such as "web" or "native".
    /// </summary>
    public string ApplicationType { get; set; } = ApplicationTypes.Web;

    /// <summary>
    /// An array of contact email addresses associated with the client, primarily used for support purposes.
    /// </summary>
    public string[]? Contacts { get; set; }

    /// <summary>
    /// A human-readable name for the client application,
    /// which can be displayed to users during the authorization process.
    /// </summary>
    public string? ClientName { get; set; }

    /// <summary>
    /// A URL pointing to a web page providing information about the client application.
    /// This is typically used to offer additional context to users during the authorization process.
    /// </summary>
    public Uri? ClientUri { get; set; }

    /// <summary>
    /// The maximum time in seconds since the user's authentication that the client accepts.
    /// Requests exceeding this time will require re-authentication of the user.
    /// </summary>
    public TimeSpan? DefaultMaxAge { get; set; }

    /// <summary>
    /// Indicates whether the authorization server must include the `auth_time` claim in the ID token.
    /// </summary>
    public bool? RequireAuthTime { get; set; }

    /// <summary>
    /// Specifies the default Authentication Context Class Reference (ACR) values for the client.
    /// These values indicate the types of authentication methods or levels of assurance required.
    /// </summary>
    public string[]? DefaultAcrValues { get; set; }

    /// <summary>
    /// Specifies the algorithm used to encrypt identity tokens issued to the client.
    /// </summary>
    public string? IdentityTokenEncryptedResponseAlgorithm { get; set; }

    /// <summary>
    /// Specifies the encryption method used to encrypt identity tokens issued to the client.
    /// </summary>
    public string? IdentityTokenEncryptedResponseEncryption { get; set; }

    /// <summary>
    /// Specifies the algorithm used to encrypt UserInfo responses returned to the client.
    /// </summary>
    public string? UserInfoEncryptedResponseAlgorithm { get; set; }

    /// <summary>
    /// Specifies the encryption method used to encrypt UserInfo responses returned to the client.
    /// </summary>
    public string? UserInfoEncryptedResponseEncryption { get; set; }

    /// <summary>
    /// RFC 9701 (<c>introspection_signed_response_alg</c>): the JWS algorithm used to sign introspection responses
    /// returned to this client as a JWT. <see cref="SigningAlgorithms.None"/> (the default) means the client receives
    /// a plain JSON introspection response; any other value opts the client into a signed JWT response.
    /// </summary>
    public string IntrospectionSignedResponseAlgorithm { get; set; } = SigningAlgorithms.None;

    /// <summary>
    /// RFC 9701 (<c>introspection_encrypted_response_alg</c>): the key-management algorithm used to encrypt
    /// introspection-response JWTs returned to the client.
    /// </summary>
    public string? IntrospectionEncryptedResponseAlgorithm { get; set; }

    /// <summary>
    /// RFC 9701 (<c>introspection_encrypted_response_enc</c>): the content-encryption algorithm used to encrypt
    /// introspection-response JWTs returned to the client.
    /// </summary>
    public string? IntrospectionEncryptedResponseEncryption { get; set; }

    /// <summary>
    /// JARM (<c>authorization_signed_response_alg</c>): the JWS algorithm used to sign authorization responses
    /// packed into a JWT for this client. Defaults to <see cref="SigningAlgorithms.RS256"/> per JARM §3; the
    /// algorithm <c>none</c> is not permitted. Only consulted when the client requests a JWT response mode.
    /// </summary>
    public string AuthorizationSignedResponseAlgorithm { get; set; } = SigningAlgorithms.RS256;

    /// <summary>
    /// JARM (<c>authorization_encrypted_response_alg</c>): the JWE key-management algorithm used to encrypt
    /// authorization responses for this client. When set, the signed response JWT is additionally encrypted
    /// (a Nested JWT). <c>null</c> means no encryption is performed.
    /// </summary>
    public string? AuthorizationEncryptedResponseAlgorithm { get; set; }

    /// <summary>
    /// JARM (<c>authorization_encrypted_response_enc</c>): the JWE content-encryption algorithm used to encrypt
    /// authorization responses for this client. Only meaningful when
    /// <see cref="AuthorizationEncryptedResponseAlgorithm"/> is set.
    /// </summary>
    public string? AuthorizationEncryptedResponseEncryption { get; set; }

    /// <summary>
    /// Specifies the algorithm required for signing request objects sent to the authorization server.
    /// </summary>
    public string? RequestObjectSigningAlgorithm { get; set; }

    /// <summary>
    /// Specifies the algorithm required for encrypting request objects sent to the authorization server.
    /// </summary>
    public string? RequestObjectEncryptionAlgorithm { get; set; }

    /// <summary>
    /// Specifies the encryption method required for encrypting request objects sent to the authorization server.
    /// </summary>
    public string? RequestObjectEncryptionMethod { get; set; }

    /// <summary>
    /// Specifies the algorithm used to sign client authentication requests at the token endpoint.
    /// </summary>
    public string? TokenEndpointAuthSigningAlgorithm { get; set; }

    /// <summary>
    /// The scope values the client is allowed to request per RFC 7591 Section 2.
    /// </summary>
    public string[]? AllowedScopes { get; set; }

    /// <summary>
    /// A unique identifier for the client software per RFC 7591 Section 2.
    /// </summary>
    public string? SoftwareId { get; set; }

    /// <summary>
    /// A version identifier for the client software per RFC 7591 Section 2.
    /// </summary>
    public string? SoftwareVersion { get; set; }

    /// <summary>
    /// Expiration time for this dynamically registered client in distributed cache.
    /// If not set, the default expiration configured in the server settings is used.
    /// Implements pseudo-sliding expiration: TTL is reset on each access.
    /// </summary>
    public TimeSpan? ExpiresAfter { get; set; }
}
