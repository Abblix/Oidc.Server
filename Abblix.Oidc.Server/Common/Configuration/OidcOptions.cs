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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// The root of the OIDC configuration. Provides the simplest way to configure and start your OIDC server.
/// </summary>
public record OidcOptions
{
	/// <summary>
	/// Configuration options for OIDC discovery. These options control how the OIDC server advertises its capabilities
	/// and endpoints to clients through the OIDC Discovery mechanism. Proper configuration ensures that clients can
	/// dynamically discover information about the OIDC server, such as URLs for authorization, token, userinfo, and
	/// JWKS endpoints, supported scopes, response types, and more.
	/// </summary>
	public DiscoveryOptions Discovery { get; set; } = new();

	/// <summary>
	/// Represents the unique identifier of the OIDC server.
	/// It is recommended to use a URL controlled by the entity operating the OIDC server, and it should be
	/// consistent across different environments to maintain trust with client applications.
	/// </summary>
	public string? Issuer { get; set; }

	/// <summary>
	/// A collection of client configurations supported by this OIDC server. Each <see cref="ClientInfo"/> object
	/// defines the settings and capabilities of a registered client, including client ID, client secrets,
	/// redirect URIs, and other OAuth2/OIDC parameters. Proper client configuration is essential for securing client
	/// applications and enabling them to interact with the OIDC server according to the OAuth2 and OIDC specifications.
	/// </summary>
	public IEnumerable<ClientInfo> Clients { get; set; } = [];

	/// <summary>
	/// The URL to a user interface or service that allows users to select an account during the authentication process.
	/// This is useful in scenarios where users have multiple accounts and need to choose which one to use for signing in.
	/// </summary>
	public Uri? AccountSelectionUri { get; set; }

	/// <summary>
	/// The URL to a user interface or service for obtaining user consent during the authentication process. Consent is
	/// often required when the client application requests access to user data or when sharing information between
	/// different parties. This URI should point to a page or API that can manage consent workflows and communicate
	/// the user's decisions back to the OIDC server.
	/// </summary>
	public Uri? ConsentUri { get; set; }

	/// <summary>
	/// The URL to a user interface or service for handling additional interactions required during the authentication
	/// process. This can include multiple factor authentication, user consent, or any custom interaction required by
	/// the authentication flow. The OIDC server can redirect users to this URI when additional interaction is needed.
	/// </summary>
	public Uri? InteractionUri { get; set; }

	/// <summary>
	/// The URL to initiate the login process. This URI is typically used in scenarios where the OIDC server needs to
	/// direct users to a specific login interface or when integrating with external identity providers. Configuring
	/// this URI allows the OIDC server to delegate the initial user authentication step to another service or UI.
	/// </summary>
	public Uri? LoginUri { get; set; }

	/// <summary>
	/// The URL of the account-creation (registration) UI the user is redirected to when a client requests
	/// user registration via <c>prompt=create</c> (Initiating User Registration via OpenID Connect 1.0).
	/// When not set, <see cref="LoginUri"/> is used instead, so hosts whose login page also offers
	/// registration need no extra configuration.
	/// </summary>
	public Uri? RegistrationUri { get; set; }

	/// <summary>
	/// The name of the parameter used by the OIDC server to pass the authorization request identifier. This parameter
	/// name is used in URLs and requests to reference specific authorization requests, especially in advanced features
	/// like Pushed Authorization Requests (PAR). Customizing this parameter name can help align with specific client
	/// requirements or naming conventions.
	/// </summary>
	public string RequestUriParameterName { get; set; } = AuthorizationRequest.Parameters.RequestUri;

	/// <summary>
	/// Specifies which OIDC endpoints are enabled on the server. This property allows for fine-grained control over
	/// the available functionality, enabling or disabling specific endpoints based on the server's role, security
	/// considerations, or operational requirements. Defaults to <see cref="OidcEndpoints.Base"/> — the core
	/// interactive OIDC set plus PAR and RP-initiated logout. The six niche or security-sensitive endpoints
	/// (CheckSession, Revocation, Introspection, dynamic client registration, CIBA and device authorization) are
	/// off by default and each turned on by its dedicated <c>AddX()</c> opt-in, which registers the feature and
	/// re-enables the corresponding flag. Leaving them off keeps a server that never opts in from advertising — or
	/// validating — an endpoint it was never asked to serve. Setting this to <see cref="OidcEndpoints.All"/> only
	/// re-advertises and routes every endpoint — the handler for each opt-in endpoint (CheckSession, Revocation,
	/// Introspection, dynamic client registration, CIBA, device authorization) is still registered solely by its
	/// <c>AddX()</c> call, so <c>All</c> restores the previous every-endpoint-on behaviour only when combined with
	/// all of those opt-in calls. Setting <c>All</c> without them advertises and routes endpoints whose handlers are
	/// absent, so every request to such an endpoint fails at runtime.
	/// </summary>
	public OidcEndpoints EnabledEndpoints { get; set; } = OidcEndpoints.Base;

	/// <summary>
	/// The collection of JSON Web Keys (JWK) used for signing tokens issued by the OIDC server.
	/// Signing tokens is a critical security measure that ensures the integrity and authenticity of the tokens.
	/// These keys are used to digitally sign ID tokens, access tokens, and other JWT tokens issued by the server,
	/// allowing clients to verify that the tokens have not been tampered with and were indeed issued by this server.
	/// It is recommended to rotate these keys periodically to maintain the security of the token signing process.
	/// </summary>
	public IReadOnlyCollection<JsonWebKey> SigningKeys { get; set; } = [];

	/// <summary>
	/// Options related to the check session mechanism in OIDC. This configuration controls how the OIDC server manages
	/// session state information, allowing clients to monitor the login session's status. Properly configuring these
	/// options ensures that clients can react to session changes (e.g., logout) in a timely and secure manner.
	/// </summary>
	public CheckSessionCookieOptions CheckSessionCookie { get; set; } = new();

	/// <summary>
	/// The duration after which a login session expires. This setting determines how long a user's authentication
	/// session remains valid before requiring re-authentication. Configuring this duration is essential for balancing
	/// security concerns with usability, particularly in environments with varying security requirements.
	/// </summary>
	public TimeSpan LoginSessionExpiresIn { get; set; } = TimeSpan.FromMinutes(10);

	/// <summary>
	/// Configuration options for registering new clients dynamically in the OIDC server. These options define default
	/// values and constraints for new client registrations, facilitating dynamic and secure client onboarding processes.
	/// </summary>
	public NewClientOptions NewClientOptions { get; init; } = new();

	/// <summary>
	/// The collection of JSON Web Keys (JWK) used for encrypting tokens or sensitive information sent to the clients.
	/// Encryption is essential for protecting sensitive data within tokens, especially when tokens are passed through
	/// less secure channels or when storing tokens on the client side.
	/// These keys are used to encrypt ID tokens and, optionally, access tokens when the OIDC server sends them to clients.
	/// Clients use the corresponding public keys to decrypt the tokens and access the contained claims.
	/// </summary>
	public IReadOnlyCollection<JsonWebKey> EncryptionKeys { get; set; } = [];

	/// <summary>
	/// The default content encryption algorithm used for encrypting JWT tokens.
	/// Per RFC 7518 Section 5, specifies how the JWT payload is encrypted using the Content Encryption Key (CEK).
	/// Common values: A256CBC-HS512, A128CBC-HS256, A256GCM, A128GCM.
	/// Defaults to A256CBC-HS512 for maximum security.
	/// </summary>
	public string DefaultContentEncryptionAlgorithm { get; set; } = EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512;

	/// <summary>
	/// The duration for which a Pushed Authorization Request (PAR) is valid. PAR is a security enhancement that allows
	/// clients to pre-register authorization requests directly with the authorization server. This duration specifies
	/// the maximum time a pre-registered request is considered valid, balancing the need for security with usability
	/// in completing the authorization process.
	/// </summary>
	public TimeSpan PushedAuthorizationRequestExpiresIn { get; set; } = TimeSpan.FromMinutes(1);

	/// <summary>
	/// The lifetime of a JARM (JWT Secured Authorization Response Mode) <c>response</c> JWT. The authorization
	/// response is consumed by the client immediately upon redirect, so a short window suffices and mostly
	/// absorbs clock skew. JARM §2.1 RECOMMENDS a maximum of 10 minutes; deployments with stricter requirements
	/// (e.g. FAPI) may shorten it.
	/// </summary>
	public TimeSpan JwtAuthorizationResponseExpiresIn { get; set; } = TimeSpan.FromMinutes(10);

	/// <summary>
	/// A JWT used for licensing and configuration validation of the OIDC service. This token contains claims that the
	/// OIDC service uses to validate its configuration, features, and licensing status, ensuring the service operates
	/// within its licensed capabilities. Proper validation of this token is crucial for the service's legal and
	/// functional compliance.
	/// </summary>
	public string? LicenseJwt { get; set; }

	/// <summary>
	/// The standard length of the authorization code generated by the server.
	/// </summary>
	public int AuthorizationCodeLength { get; set; } = 64;

	/// <summary>
	/// The standard length of the request URI generated by the server for Pushed Authorization Requests (PAR).
	/// </summary>
	public int RequestUriLength { get; set; } = 64;

	/// <summary>
	/// The supported scopes and their respective claim types, which outline the access permissions and associated data
	/// that clients can request.
	/// This setting determines what information and operations are available to different clients based on the scopes
	/// they request during authorization.
	/// </summary>
	public ScopeDefinition[]? Scopes { get; set; }

	/// <summary>
	/// The resource definitions supported by the OIDC server. This setting outlines the resources that clients
	/// can request access to during authorization, ensuring the OIDC server can enforce access control policies
	/// and permissions based on these definitions.
	/// </summary>
	public ResourceDefinition[]? Resources { get; set; }

	/// <summary>
	/// Configuration options for the backchannel authentication flow,
	/// used in scenarios such as Client-Initiated Backchannel Authentication (CIBA).
	/// </summary>
	public BackChannelAuthenticationOptions BackChannelAuthentication { get; set; } = new();

	/// <summary>
	/// Configuration options for the Device Authorization Grant (RFC 8628),
	/// used for devices with limited input capabilities.
	/// </summary>
	public DeviceAuthorizationOptions? DeviceAuthorization { get; set; }

	/// <summary>
	/// Specifies the length of session identifiers used by the OIDC server.
	/// The length determines the uniqueness and security of the session identifiers.
	/// </summary>
	public int SessionIdLength { get; set; } = 64;

	/// <summary>
	/// Specifies the length of token identifiers used by the OIDC server.
	/// This value determines the length of the unique ID assigned to tokens.
	/// </summary>
	public int TokenIdLength { get; set; } = 64;

	/// <summary>
	/// Specifies the length, in random bytes, of the refresh-token grant identifier (the <c>grant_id</c>
	/// claim). The grant id binds every refresh token of one authorization grant into a single lineage for
	/// rotation and family revocation (RFC 9700 Section 4.14.2), so it must carry enough entropy to make the
	/// identifier unguessable.
	/// </summary>
	public int GrantIdLength { get; set; } = 64;

	/// <summary>
	/// Determines whether the OIDC server requires Pushed Authorization Requests (PAR).
	/// </summary>
	public bool RequirePushedAuthorizationRequests { get; set; } = false;

	/// <summary>
	/// Determines whether request objects must be signed by the client,
	/// enhancing security for certain sensitive operations.
	/// </summary>
	public bool RequireSignedRequestObject { get; set; } = false;

	/// <summary>
	/// Governs how a request object resolves a parameter that appears both inside the object and in the
	/// OAuth query syntax — a choice between two specifications. When <c>false</c> (the default), request-object
	/// processing follows the OpenID Connect Core §6.1 merge semantics: the object's values supersede those
	/// passed outside it, but a parameter passed only outside the object is still used. Set to <c>true</c> for
	/// the strict RFC 9101 §6.3 rule, where the authorization request is exactly the content of the object and
	/// any parameter passed outside it is ignored ("the authorization server MUST only use the parameters in
	/// the Request Object"). The strict rule suits FAPI-style OAuth deployments; as an OpenID Provider the
	/// server defaults to the merge behaviour, since strict processing would drop parameters that existing
	/// OpenID Connect clients commonly pass outside the object. A client held to the FAPI 2.0 security profile
	/// is processed strictly regardless of this global default.
	/// This switch affects only parameter exclusivity; the other RFC 9101 §6.3 requirement — that a
	/// <c>client_id</c> or <c>response_type</c> present both inside and outside the object be identical — is
	/// enforced in both modes and cannot be turned off.
	/// </summary>
	public bool IgnoreParametersOutsideRequestObject { get; set; } = false;

	/// <summary>
	/// Determines whether the client registration endpoint requires an initial access token
	/// in the Authorization header per RFC 7591 Section 3.
	/// When <c>true</c>, POST requests to the registration endpoint must include a valid
	/// Bearer token. When <c>false</c>, open registration is allowed.
	/// </summary>
	public bool RequireInitialAccessToken { get; set; } = true;

	/// <summary>
	/// The set of revoked initial access token identifiers (JWT subject claims).
	/// Tokens whose subject appears in this set will be rejected during client registration.
	/// For production use with large or dynamic revocation lists, replace
	/// <see cref="Endpoints.DynamicClientManagement.Interfaces.IInitialAccessTokenRevocationProvider"/>
	/// with a database- or cache-backed implementation.
	/// </summary>
	public HashSet<string> RevokedInitialAccessTokenSubjects { get; set; } = [];

	/// <summary>
	/// Configuration options for JWT Bearer grant type (RFC 7523).
	/// Defines trusted external identity providers whose JWT assertions can be exchanged for access tokens.
	/// </summary>
	public JwtBearerOptions JwtBearer { get; set; } = new();

	/// <summary>
	/// Configuration options for software statement validation per RFC 7591 Section 2.3.
	/// </summary>
	public SoftwareStatementOptions SoftwareStatement { get; set; } = new();

	/// <summary>
	/// Configuration options for OAuth 2.0 DPoP (RFC 9449), governing the
	/// <see cref="ProofValidator"/> behaviour and related primitives.
	/// </summary>
	public DPoPOptions DPoP { get; set; } = new();

	/// <summary>
	/// The server-wide default security profile, applied to every client whose own
	/// <see cref="ClientInfo.SecurityProfile"/> is left unset (<c>null</c>). A single-profile
	/// deployment sets this once — for example to <see cref="ClientSecurityProfile.Fapi2"/> — and
	/// every client without an explicit profile inherits the FAPI 2.0 control bundle; an individual
	/// client opts out by setting its own profile to <see cref="ClientSecurityProfile.None"/>. The
	/// default <see cref="ClientSecurityProfile.None"/> leaves unprofiled clients governed by their
	/// individual metadata flags, so existing deployments are unaffected.
	/// </summary>
	public ClientSecurityProfile DefaultSecurityProfile { get; set; } = ClientSecurityProfile.None;

	/// <summary>
	/// Enables detection of a client reusing a constant PKCE <c>code_challenge</c> or OpenID Connect
	/// <c>nonce</c> across authorization requests, which defeats the transaction-binding those values provide
	/// (RFC 9700 Section 2.1.1 encourages the authorization server to make a reasonable effort to detect and
	/// prevent it). When set, the server records each value at the moment it issues an authorization code and
	/// rejects a later authorization request from the same client that repeats a value within this interval.
	/// Recording at code issuance — not on every authorization request — means re-processing one request
	/// across a login or consent redirect is not flagged. Left <c>null</c> (the default) the check is off:
	/// a conforming client generates a fresh value per request and is never affected, but a client that
	/// incorrectly reuses a value across separate authorizations would then be rejected, so it is opt-in.
	/// </summary>
	public TimeSpan? PkceAndNonceReuseDetectionInterval { get; set; }
}
