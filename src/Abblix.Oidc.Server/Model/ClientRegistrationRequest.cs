// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.DeclarativeBinding;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents metadata for an OAuth2 client based on the OpenID Connect discovery specification.
/// </summary>
/// <remarks>
/// See the OpenID Connect Registration specification at https://openid.net/specs/openid-connect-registration-1_0.html.
/// </remarks>
public record ClientRegistrationRequest
{
    /// <summary>
    /// The Authorization header from the HTTP request, used for initial access token validation
    /// per RFC 7591 Section 3. This is a transport-level property, not part of the registration metadata.
    /// </summary>
    [JsonIgnore]
    public AuthenticationHeaderValue? AuthorizationHeader { get; init; }

    /// <summary>
    /// The <c>redirect_uris</c> array (RFC 7591 §2) listing every absolute URI the OP may use to deliver
    /// authorization responses to this client. An authorization request must then specify a redirect URI
    /// that exactly matches one of these values.
    /// </summary>
    /// <remarks>
    /// Deliberately not required at the model layer, because whether it is required depends on another
    /// member of the same request. RFC 7591 section 2 asks for it only for grant types that redirect, and
    /// <c>RedirectUrisValidator</c> already applies exactly that rule - it demands at least one entry when
    /// the requested grants include the authorization code, implicit or refresh token, and says nothing
    /// otherwise. A declarative constraint here ran first and refused a device-flow or CIBA client, which
    /// has no user agent to redirect, with a transport-level 400 naming a C# property rather than the
    /// protocol error the endpoint owes the caller. This mirrors the repository rule that a declarative
    /// value constraint belongs on a request model only when the specification fixes the rule outright.
    /// </remarks>
    [JsonPropertyName(Parameters.RedirectUris)]
    public Uri[]? RedirectUris { get; init; }

    /// <summary>
    /// The <c>response_types</c> the client intends to use (RFC 7591 §2). Each entry is itself a
    /// space-separated combination of <c>code</c>, <c>token</c>, and/or <c>id_token</c>; the array therefore
    /// represents the full set of response type combinations registered for this client.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: authorization response processors
    /// are registered per flow (the implicit flow is off by default), and the registration pipeline
    /// already validates every requested response type against the set the server actually supports
    /// and advertises in its discovery document.
    /// </remarks>
    [JsonPropertyName(Parameters.ResponseTypes)]
    [JsonConverter(typeof(ArrayConverter<string[], SpaceSeparatedValuesConverter>))]
    public string[][] ResponseTypes { get; init; } = [[Common.Constants.ResponseTypes.Code]];

    /// <summary>
    /// The <c>grant_types</c> the client will request at the token endpoint per RFC 7591 §2,
    /// for example <c>authorization_code</c>, <c>refresh_token</c>, or <c>urn:openid:params:grant-type:ciba</c>.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: grant handlers are an extensible
    /// set, and the registration pipeline already validates every requested grant against the
    /// union the server actually supports and advertises in its discovery document.
    /// </remarks>
    [JsonPropertyName(Parameters.GrantTypes)]
    public string[] GrantTypes { get; init; } = [Common.Constants.GrantTypes.AuthorizationCode];

    /// <summary>
    /// The <c>application_type</c> declared at registration (OIDC Dynamic Client Registration §2),
    /// typically <c>web</c> or <c>native</c>. Influences allowed redirect URI schemes and other policy.
    /// </summary>
    [JsonPropertyName(Parameters.ApplicationType)]
    [AllowedValues(ApplicationTypes.Web, ApplicationTypes.Native)]
    public string ApplicationType { get; init; } = ApplicationTypes.Web;

    /// <summary>
    /// The <c>contacts</c> array (RFC 7591 §2): email addresses of people responsible for this client,
    /// used for operational notifications by the authorization server.
    /// </summary>
    [JsonPropertyName(Parameters.Contacts)]
    public string[]? Contacts { get; init; }

    /// <summary>
    /// A client-proposed <c>client_id</c>. Servers MAY ignore this and assign their own identifier;
    /// when accepted, the value is echoed back in the registration response.
    /// </summary>
    [JsonPropertyName(Parameters.ClientId)]
    public string? ClientId { get; init; }

    /// <summary>
    /// The <c>client_name</c> (RFC 7591 §2): a human-readable display name for the client, shown to end-users
    /// on consent screens.
    /// </summary>
    [JsonPropertyName(Parameters.ClientName)]
    public string? ClientName { get; init; }

    /// <summary>
    /// The <c>logo_uri</c>: an absolute URL of an image displayed to end-users alongside <see cref="ClientName"/>
    /// during authentication and consent.
    /// </summary>
    [JsonPropertyName(Parameters.LogoUri)]
    [AbsoluteUri]
    public Uri? LogoUri { get; init; }

    /// <summary>
    /// The <c>client_uri</c>: an absolute URL of the client application's home page, shown to end-users
    /// alongside <see cref="ClientName"/>.
    /// </summary>
    [JsonPropertyName(Parameters.ClientUri)]
    [AbsoluteUri]
    public Uri? ClientUri { get; init; }

    /// <summary>
    /// The <c>policy_uri</c>: an absolute URL the relying party provides describing how end-user
    /// profile data is used.
    /// </summary>
    [JsonPropertyName(Parameters.PolicyUri)]
    [AbsoluteUri]
    public Uri? PolicyUri { get; init; }

    /// <summary>
    /// The <c>tos_uri</c>: an absolute URL where the relying party publishes its terms of service.
    /// </summary>
    [JsonPropertyName(Parameters.TosUri)]
    [AbsoluteUri]
    public Uri? TermsOfServiceUri { get; init; }

    /// <summary>
    /// The <c>jwks_uri</c>: an absolute URL where the client publishes its JSON Web Key Set, used by the OP
    /// to verify signed assertions and to encrypt content addressed to the client.
    /// </summary>
    [JsonPropertyName(Parameters.JwksUri)]
    [AbsoluteUri]
    public Uri? JwksUri { get; init; }

    /// <summary>
    /// The inline <c>jwks</c> value: the client's JSON Web Key Set provided directly in registration metadata,
    /// used as an alternative to <see cref="JwksUri"/>. Only one of the two may be provided per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(Parameters.Jwks)]
    public JsonWebKeySet? Jwks { get; init; }

    /// <summary>
    /// The <c>sector_identifier_uri</c> (OIDC Core §8.1): an absolute HTTPS URL whose host is used to compute
    /// pairwise pseudonymous subject identifiers, allowing multiple registered redirect URIs to share the same
    /// pairwise sector.
    /// </summary>
    [JsonPropertyName(Parameters.SectorIdentifierUri)]
    [AbsoluteUri]
    public Uri? SectorIdentifierUri { get; init; }

    /// <summary>
    /// The <c>subject_type</c> (OIDC Core §8) requested for ID Token <c>sub</c> claim generation:
    /// <c>public</c> (same identifier across clients) or <c>pairwise</c> (per-sector pseudonymous).
    /// </summary>
    [JsonPropertyName(Parameters.SubjectType)]
    [AllowedValues(SubjectTypes.Public, SubjectTypes.Pairwise)]
    public string? SubjectType { get; init; } = SubjectTypes.Public;

    /// <summary>
    /// The <c>id_token_signed_response_alg</c> (OIDC Core §2): the JWS <c>alg</c> the OP must use to sign
    /// ID Tokens issued to this client (e.g. <c>RS256</c>, <c>ES256</c>).
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.IdTokenSignedResponseAlg)]
    public string? IdTokenSignedResponseAlg { get; init; }

    /// <summary>
    /// The <c>id_token_encrypted_response_alg</c>: the JWE key-management algorithm the OP must use when
    /// encrypting ID Tokens for this client.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.IdTokenEncryptedResponseAlg)]
    public string? IdTokenEncryptedResponseAlg { get; init; }

    /// <summary>
    /// The <c>id_token_encrypted_response_enc</c>: the JWE content-encryption algorithm paired with
    /// <see cref="IdTokenEncryptedResponseAlg"/> for ID Tokens issued to this client.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.IdTokenEncryptedResponseEnc)]
    public string? IdTokenEncryptedResponseEnc { get; init; }

    /// <summary>
    /// The <c>userinfo_signed_response_alg</c>: the JWS algorithm the OP must use when signing UserInfo
    /// responses returned to this client. When omitted, UserInfo is returned as plain JSON.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.UserInfoSignedResponseAlg)]
    public string? UserInfoSignedResponseAlg { get; init; }

    /// <summary>
    /// The <c>userinfo_encrypted_response_alg</c>: the JWE key-management algorithm the OP must use when
    /// encrypting UserInfo responses for this client.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseAlg)]
    public string? UserInfoEncryptedResponseAlg { get; init; }

    /// <summary>
    /// The <c>userinfo_encrypted_response_enc</c>: the JWE content-encryption algorithm paired with
    /// <see cref="UserInfoEncryptedResponseAlg"/> for UserInfo responses to this client.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseEnc)]
    public string? UserInfoEncryptedResponseEnc { get; init; }

    /// <summary>
    /// The <c>introspection_signed_response_alg</c> (RFC 9701): the JWS algorithm the OP must use when signing
    /// introspection responses returned to this client. When omitted, introspection is returned as plain JSON.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.IntrospectionSignedResponseAlg)]
    public string? IntrospectionSignedResponseAlg { get; init; }

    /// <summary>
    /// The <c>introspection_encrypted_response_alg</c> (RFC 9701): the JWE key-management algorithm the OP must use
    /// when encrypting introspection responses for this client.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.IntrospectionEncryptedResponseAlg)]
    public string? IntrospectionEncryptedResponseAlg { get; init; }

    /// <summary>
    /// The <c>introspection_encrypted_response_enc</c> (RFC 9701): the JWE content-encryption algorithm paired with
    /// <see cref="IntrospectionEncryptedResponseAlg"/> for introspection responses to this client.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.IntrospectionEncryptedResponseEnc)]
    public string? IntrospectionEncryptedResponseEnc { get; init; }

    /// <summary>
    /// The <c>authorization_signed_response_alg</c> (JARM §3): the JWS algorithm the OP must use to sign
    /// authorization responses packed into a JWT for this client. Defaults to <c>RS256</c>; <c>none</c> is
    /// not permitted.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.AuthorizationSignedResponseAlg)]
    public string? AuthorizationSignedResponseAlg { get; init; }

    /// <summary>
    /// The <c>authorization_encrypted_response_alg</c> (JARM §3): the JWE key-management algorithm the OP must
    /// use when encrypting authorization responses for this client. When set, the signed response JWT is
    /// additionally encrypted (a Nested JWT).
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.AuthorizationEncryptedResponseAlg)]
    public string? AuthorizationEncryptedResponseAlg { get; init; }

    /// <summary>
    /// The <c>authorization_encrypted_response_enc</c> (JARM §3): the JWE content-encryption algorithm paired
    /// with <see cref="AuthorizationEncryptedResponseAlg"/> for authorization responses to this client.
    /// Defaults to <c>A128CBC-HS256</c> when the encryption algorithm is set.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.AuthorizationEncryptedResponseEnc)]
    public string? AuthorizationEncryptedResponseEnc { get; init; }

    /// <summary>
    /// The <c>request_object_signing_alg</c>: the JWS algorithm the client uses when signing Request Objects
    /// (OIDC Core §6) sent to the authorization endpoint. <c>none</c> indicates an unsigned Request Object.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.RequestObjectSigningAlg)]
    public string? RequestObjectSigningAlg { get; init; }

    /// <summary>
    /// The <c>request_object_encryption_alg</c>: the JWE key-management algorithm the client may use when
    /// encrypting Request Objects sent to the OP.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.RequestObjectEncryptionAlg)]
    public string? RequestObjectEncryptionAlg { get; init; }

    /// <summary>
    /// The <c>request_object_encryption_enc</c>: the JWE content-encryption algorithm paired with
    /// <see cref="RequestObjectEncryptionAlg"/> for Request Objects.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.RequestObjectEncryptionEnc)]
    public string? RequestObjectEncryptionEnc { get; init; }

    /// <summary>
    /// The <c>token_endpoint_auth_method</c> (RFC 7591 §2): the client authentication method used at the
    /// token endpoint, such as <c>client_secret_basic</c>, <c>client_secret_post</c>, <c>private_key_jwt</c>,
    /// <c>tls_client_auth</c>, or <c>none</c>.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: client authenticators are an
    /// extensible set, and the registration pipeline already validates the value against the
    /// methods the server actually supports and announces in its discovery document.
    /// </remarks>
    [JsonPropertyName(Parameters.TokenEndpointAuthMethod)]
    public string TokenEndpointAuthMethod { get; init; } = ClientAuthenticationMethods.ClientSecretBasic;

    /// <summary>
    /// The <c>token_endpoint_auth_signing_alg</c>: the JWS algorithm the client uses when signing
    /// authentication assertions for <c>private_key_jwt</c> or <c>client_secret_jwt</c> at the token endpoint.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.TokenEndpointAuthSigningAlg)]
    public string? TokenEndpointAuthSigningAlg { get; init; }

    // RFC 8705 - tls_client_auth metadata
    /// <summary>
    /// Exact Subject Distinguished Name the client certificate must present when using tls_client_auth.
    /// </summary>
    [JsonPropertyName(Parameters.TlsClientAuthSubjectDn)]
    public string? TlsClientAuthSubjectDn { get; init; }

    /// <summary>
    /// Required DNS Subject Alternative Names for tls_client_auth.
    /// </summary>
    [JsonPropertyName(Parameters.TlsClientAuthSanDns)]
    public string[]? TlsClientAuthSanDns { get; init; }

    /// <summary>
    /// Required URI Subject Alternative Names for tls_client_auth.
    /// </summary>
    [JsonPropertyName(Parameters.TlsClientAuthSanUri)]
    public Uri[]? TlsClientAuthSanUri { get; init; }

    /// <summary>
    /// Required IP Subject Alternative Names for tls_client_auth.
    /// </summary>
    [JsonPropertyName(Parameters.TlsClientAuthSanIp)]
    public string[]? TlsClientAuthSanIp { get; init; }

    /// <summary>
    /// Required email Subject Alternative Names for tls_client_auth.
    /// </summary>
    [JsonPropertyName(Parameters.TlsClientAuthSanEmail)]
    public string[]? TlsClientAuthSanEmail { get; init; }

    /// <summary>
    /// The <c>default_max_age</c> (OIDC Dynamic Client Registration §2): the default maximum elapsed time
    /// since the user's last authentication that the OP should honor for authorization requests from this
    /// client. Serialized as an integer number of seconds.
    /// </summary>
    [JsonPropertyName(Parameters.DefaultMaxAge)]
    public TimeSpan? DefaultMaxAge { get; init; }

    /// <summary>
    /// The <c>require_auth_time</c> flag: when <c>true</c>, the OP must always include the <c>auth_time</c>
    /// claim in ID Tokens issued to this client.
    /// </summary>
    [JsonPropertyName(Parameters.RequireAuthTime)]
    public bool? RequireAuthTime { get; init; }

    /// <summary>
    /// The <c>default_acr_values</c>: an ordered list of ACR values the OP should use as defaults for this
    /// client when the authorization request omits <c>acr_values</c>.
    /// </summary>
    [JsonPropertyName(Parameters.DefaultAcrValues)]
    public string[]? DefaultAcrValues { get; init; }

    /// <summary>
    /// The <c>initiate_login_uri</c>: an absolute URL the OP can call to initiate a login flow at the client,
    /// for example to recover an interrupted session.
    /// </summary>
    [JsonPropertyName(Parameters.InitiateLoginUri)]
    [AbsoluteUri]
    public Uri? InitiateLoginUri { get; init; }

    /// <summary>
    /// The <c>request_uris</c> (OIDC Core §6.2): URIs that the OP may pre-fetch and cache for use as
    /// <c>request_uri</c> values in authorization requests from this client.
    /// </summary>
    [JsonPropertyName(Parameters.RequestUris)]
    public Uri[]? RequestUris { get; init; }

    /// <summary>
    /// When <c>true</c>, this client must present a PKCE <c>code_challenge</c> on every authorization request
    /// per RFC 7636. Server extension to RFC 7591 metadata.
    /// </summary>
    /// <remarks>
    /// Null when the registration request does not state it, so that the default lives in one place -
    /// <see cref="Features.ClientInformation.ClientInfo.PkceRequired"/>, which requires PKCE. A non-null default here
    /// would be copied onto the registered client and win over that one, leaving a dynamically registered
    /// client without the protection a statically configured client gets, which is the opposite of what
    /// RFC 9700 section 2.1.1 asks of an authorization server.
    /// </remarks>
    [JsonPropertyName(Parameters.PkceRequired)]
    public bool? PkceRequired { get; init; }

    /// <summary>
    /// When <c>true</c>, the client is permitted to request the <c>offline_access</c> scope and receive
    /// refresh tokens. Server extension to RFC 7591 metadata; defaults to <c>true</c>.
    /// </summary>
    [JsonPropertyName(Parameters.OfflineAccessAllowed)]
    public bool? OfflineAccessAllowed { get; init; } = true;

    /// <summary>
    /// The <c>dpop_bound_access_tokens</c> client metadata per RFC 9449 §5.2: when <c>true</c>,
    /// access tokens issued to this client must be sender-constrained via DPoP (the server
    /// will require a valid DPoP proof on every token request and bind <c>cnf.jkt</c> on
    /// the issued token). Maps to <see cref="Features.ClientInformation.ClientInfo.RequireDPoP"/>. When omitted, treated
    /// as <c>false</c> per RFC 9449 §5.2.
    /// </summary>
    [JsonPropertyName(Parameters.DpopBoundAccessTokens)]
    public bool? DpopBoundAccessTokens { get; init; }

    /// <summary>
    /// The <c>require_pushed_authorization_requests</c> client metadata per RFC 9126 §6: when
    /// <c>true</c>, pushed authorization requests are the only way this client may start an
    /// authorization flow. Maps to
    /// <see cref="Features.ClientInformation.ClientInfo.RequirePushedAuthorizationRequests"/>.
    /// When omitted, treated as <c>false</c>.
    /// </summary>
    [JsonPropertyName(Parameters.RequirePushedAuthorizationRequests)]
    public bool? RequirePushedAuthorizationRequests { get; init; }

    /// <summary>
    /// The <c>require_signed_request_object</c> client metadata per RFC 9101 §10.5: when
    /// <c>true</c>, the client must deliver its authorization request parameters as a signed
    /// request object. Maps to
    /// <see cref="Features.ClientInformation.ClientInfo.RequireSignedRequestObject"/>.
    /// When omitted, treated as <c>false</c>.
    /// </summary>
    [JsonPropertyName(Parameters.RequireSignedRequestObject)]
    public bool? RequireSignedRequestObject { get; init; }

    /// <summary>
    /// The <c>tls_client_certificate_bound_access_tokens</c> client metadata per RFC 8705 §3.4:
    /// when <c>true</c>, access tokens issued to this client are certificate-bound whenever the
    /// token request arrives over mutual TLS, independently of the authentication method. Maps to
    /// <see cref="Features.ClientInformation.ClientInfo.TlsClientCertificateBoundAccessTokens"/>.
    /// When omitted, treated as <c>false</c>.
    /// </summary>
    [JsonPropertyName(Parameters.TlsClientCertificateBoundAccessTokens)]
    public bool? TlsClientCertificateBoundAccessTokens { get; init; }

    /// <summary>
    /// The <c>authorization_details_types</c> client metadata per RFC 9396 §10: the per-client
    /// allowlist of authorization-detail <c>type</c> values this client may use in RAR requests.
    /// Maps to <see cref="Features.ClientInformation.ClientInfo.AuthorizationDetailsTypes"/>.
    /// <c>null</c> means no per-client constraint; empty array means this client cannot use RAR.
    /// </summary>
    [JsonPropertyName(Parameters.AuthorizationDetailsTypes)]
    public string[]? AuthorizationDetailsTypes { get; init; }

    /// <summary>
    /// Non-standard extension: the per-client allowlist of RFC 8693 <c>subject_token_type</c> URIs this
    /// client may submit to the Token Exchange grant. RFC 8693 does not standardise a registration
    /// parameter for this, so the property is exposed under the non-standard
    /// <c>token_exchange_subject_token_types</c> name. Maps to
    /// <see cref="Features.ClientInformation.ClientInfo.TokenExchangeAllowedSubjectTokenTypes"/>.
    /// <c>null</c> means no per-client constraint; empty array means the client cannot use
    /// Token Exchange at all.
    /// </summary>
    [JsonPropertyName(Parameters.TokenExchangeSubjectTokenTypes)]
    public string[]? TokenExchangeSubjectTokenTypes { get; init; }

    /// <summary>
    /// Non-standard extension: the per-client allowlist of RFC 8693 <c>audience</c> values this
    /// client may request when exchanging a token. RFC 8693 does not standardise a registration
    /// parameter for this, so the property is exposed under the non-standard
    /// <c>token_exchange_audiences</c> name. Maps to
    /// <see cref="Features.ClientInformation.ClientInfo.TokenExchangeAllowedAudiences"/>.
    /// Default-deny: <c>null</c> or empty means the client may not request any <c>audience</c>;
    /// a non-empty array is the allowlist of accepted values.
    /// </summary>
    [JsonPropertyName(Parameters.TokenExchangeAudiences)]
    public string[]? TokenExchangeAudiences { get; init; }

    /// <summary>
    /// The <c>backchannel_logout_uri</c> (OIDC Back-Channel Logout 1.0): an absolute URL at the client
    /// that the OP calls server-to-server with a logout token to terminate the user's session at the client.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelLogoutUri)]
    [AbsoluteUri]
    public Uri? BackChannelLogoutUri { get; init; }

    /// <summary>
    /// The <c>backchannel_logout_session_required</c> flag: when <c>true</c>, the OP must include the
    /// <c>sid</c> claim in the back-channel logout token so the client can identify the session being ended.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelLogoutSessionRequired)]
    public bool? BackChannelLogoutSessionRequired { get; init; }

    /// <summary>
    /// The <c>frontchannel_logout_uri</c> (OIDC Front-Channel Logout 1.0): an absolute URL the OP renders
    /// in an iframe inside its logout page so the client can clear its own session in the user agent.
    /// </summary>
    [JsonPropertyName(Parameters.FrontChannelLogoutUri)]
    [AbsoluteUri]
    public Uri? FrontChannelLogoutUri { get; init; }

    /// <summary>
    /// The <c>frontchannel_logout_session_required</c> flag: when <c>true</c>, the OP must append <c>iss</c>
    /// and <c>sid</c> query parameters to <see cref="FrontChannelLogoutUri"/> so the client can target the
    /// specific session being ended.
    /// </summary>
    [JsonPropertyName(Parameters.FrontChannelLogoutSessionRequired)]
    public bool? FrontChannelLogoutSessionRequired { get; init; }

    /// <summary>
    /// The <c>post_logout_redirect_uris</c> (OIDC RP-Initiated Logout): the absolute URIs the OP may redirect
    /// the user agent to after RP-initiated logout. Logout requests must specify a
    /// <c>post_logout_redirect_uri</c> that exactly matches one of these.
    /// </summary>
    [JsonPropertyName(Parameters.PostLogoutRedirectUris)]
    [ElementsRequired]
    public Uri[] PostLogoutRedirectUris { get; init; } = [];

    /// <summary>
    /// The backchannel token delivery mode to be used by this client. This determines how tokens are delivered
    /// during backchannel authentication.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelTokenDeliveryMode)]
    [AllowedValues(
        BackchannelTokenDeliveryModes.Ping,
        BackchannelTokenDeliveryModes.Poll,
        BackchannelTokenDeliveryModes.Push)]
    public string? BackChannelTokenDeliveryMode { get; init; }

    /// <summary>
    /// The endpoint where backchannel client notifications are sent for this client.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelClientNotificationEndpoint)]
    [AbsoluteUri]
    public Uri? BackChannelClientNotificationEndpoint { get; init; }

    /// <summary>
    /// The signing algorithm used for backchannel authentication requests sent to this client.
    /// </summary>
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the permissible algorithms are
    /// determined at runtime by the keyed signing/encryption registrations, so a static list
    /// would misstate the host's actual capabilities.
    /// </remarks>
    [JsonPropertyName(Parameters.BackChannelAuthenticationRequestSigningAlg)]
    public string? BackChannelAuthenticationRequestSigningAlg { get; init; }

    /// <summary>
    /// Indicates whether the backchannel authentication process supports user codes for this client.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelUserCodeParameter)]
    public bool BackChannelUserCodeParameter { get; init; }

    /// <summary>
    /// A space-separated list of scope values the client will use per RFC 7591 Section 2.
    /// </summary>
    [JsonPropertyName(Parameters.Scope)]
    [JsonConverter(typeof(SpaceSeparatedValuesConverter))]
    public string[]? Scope { get; set; }

    /// <summary>
    /// A unique identifier string assigned by the client developer or software publisher
    /// to identify the client software per RFC 7591 Section 2.
    /// </summary>
    [JsonPropertyName(Parameters.SoftwareId)]
    public string? SoftwareId { get; set; }

    /// <summary>
    /// A version identifier string for the client software per RFC 7591 Section 2.
    /// </summary>
    [JsonPropertyName(Parameters.SoftwareVersion)]
    public string? SoftwareVersion { get; set; }

    /// <summary>
    /// A digitally signed or MACed JWT that asserts metadata values about the client software,
    /// issued by a third-party software statement issuer per RFC 7591 Section 2.3.
    /// </summary>
    [JsonPropertyName(Parameters.SoftwareStatement)]
    public string? SoftwareStatement { get; set; }

    /// <summary>
    /// Wire-level parameter names for the dynamic client registration request (RFC 7591 and OpenID Connect
    /// Dynamic Client Registration 1.0). Each constant is the JSON member name expected on the registration
    /// payload sent to the registration endpoint.
    /// </summary>
    public static class Parameters
    {
        /// <summary>The <c>redirect_uris</c> registration parameter listing the absolute URIs the OP may
        /// use to deliver authorization responses to this client.</summary>
        public const string RedirectUris = "redirect_uris";

        /// <summary>The <c>response_types</c> registration parameter declaring the response type values
        /// the client intends to use at the authorization endpoint.</summary>
        public const string ResponseTypes = "response_types";

        /// <summary>The <c>grant_types</c> registration parameter declaring the grant type values the
        /// client will use at the token endpoint.</summary>
        public const string GrantTypes = "grant_types";

        /// <summary>The <c>application_type</c> registration parameter that classifies the client as
        /// a <c>web</c> or <c>native</c> application.</summary>
        public const string ApplicationType = "application_type";

        /// <summary>The <c>contacts</c> registration parameter listing email addresses of people
        /// responsible for the client.</summary>
        public const string Contacts = "contacts";

        /// <summary>The <c>client_id</c> registration parameter; a client-proposed identifier that the OP
        /// may accept or ignore.</summary>
        public const string ClientId = "client_id";

        /// <summary>The <c>client_name</c> registration parameter providing a human-readable display name
        /// shown to end-users on consent screens.</summary>
        public const string ClientName = "client_name";

        /// <summary>The <c>logo_uri</c> registration parameter pointing to an image rendered next to the
        /// client name during authentication and consent.</summary>
        public const string LogoUri = "logo_uri";

        /// <summary>The <c>client_uri</c> registration parameter pointing to the client application's
        /// home page.</summary>
        public const string ClientUri = "client_uri";

        /// <summary>The <c>policy_uri</c> registration parameter pointing to the client's privacy policy.
        /// </summary>
        public const string PolicyUri = "policy_uri";

        /// <summary>The <c>tos_uri</c> registration parameter pointing to the client's terms of service.
        /// </summary>
        public const string TosUri = "tos_uri";

        /// <summary>The <c>jwks_uri</c> registration parameter referencing the client's published JSON Web
        /// Key Set.</summary>
        public const string JwksUri = "jwks_uri";

        /// <summary>The <c>jwks</c> registration parameter carrying the client's JSON Web Key Set inline.
        /// </summary>
        public const string Jwks = "jwks";

        /// <summary>The <c>sector_identifier_uri</c> registration parameter used when computing pairwise
        /// pseudonymous subject identifiers.</summary>
        public const string SectorIdentifierUri = "sector_identifier_uri";

        /// <summary>The <c>subject_type</c> registration parameter selecting <c>public</c> or <c>pairwise</c>
        /// ID Token <c>sub</c> values.</summary>
        public const string SubjectType = "subject_type";

        /// <summary>The <c>id_token_signed_response_alg</c> registration parameter naming the JWS algorithm
        /// the OP must use to sign ID Tokens for this client.</summary>
        public const string IdTokenSignedResponseAlg = "id_token_signed_response_alg";

        /// <summary>The <c>id_token_encrypted_response_alg</c> registration parameter naming the JWE
        /// key-management algorithm used when encrypting ID Tokens.</summary>
        public const string IdTokenEncryptedResponseAlg = "id_token_encrypted_response_alg";

        /// <summary>The <c>id_token_encrypted_response_enc</c> registration parameter naming the JWE
        /// content-encryption algorithm used with the key-management algorithm above.</summary>
        public const string IdTokenEncryptedResponseEnc = "id_token_encrypted_response_enc";

        /// <summary>The <c>userinfo_signed_response_alg</c> registration parameter naming the JWS algorithm
        /// the OP must use when signing UserInfo responses for this client.</summary>
        public const string UserInfoSignedResponseAlg = "userinfo_signed_response_alg";

        /// <summary>The <c>userinfo_encrypted_response_alg</c> registration parameter naming the JWE
        /// key-management algorithm used when encrypting UserInfo responses.</summary>
        public const string UserInfoEncryptedResponseAlg = "userinfo_encrypted_response_alg";

        /// <summary>The <c>userinfo_encrypted_response_enc</c> registration parameter naming the JWE
        /// content-encryption algorithm for UserInfo responses.</summary>
        public const string UserInfoEncryptedResponseEnc = "userinfo_encrypted_response_enc";

        /// <summary>The <c>introspection_signed_response_alg</c> registration parameter (RFC 9701) naming the JWS
        /// algorithm the OP must use when signing introspection responses for this client.</summary>
        public const string IntrospectionSignedResponseAlg = "introspection_signed_response_alg";

        /// <summary>The <c>introspection_encrypted_response_alg</c> registration parameter (RFC 9701) naming the JWE
        /// key-management algorithm used when encrypting introspection responses.</summary>
        public const string IntrospectionEncryptedResponseAlg = "introspection_encrypted_response_alg";

        /// <summary>The <c>introspection_encrypted_response_enc</c> registration parameter (RFC 9701) naming the JWE
        /// content-encryption algorithm for introspection responses.</summary>
        public const string IntrospectionEncryptedResponseEnc = "introspection_encrypted_response_enc";

        /// <summary>The <c>authorization_signed_response_alg</c> registration parameter naming the JWS algorithm
        /// the OP must use to sign JARM authorization responses for this client.</summary>
        public const string AuthorizationSignedResponseAlg = "authorization_signed_response_alg";

        /// <summary>The <c>authorization_encrypted_response_alg</c> registration parameter naming the JWE
        /// key-management algorithm used when encrypting JARM authorization responses.</summary>
        public const string AuthorizationEncryptedResponseAlg = "authorization_encrypted_response_alg";

        /// <summary>The <c>authorization_encrypted_response_enc</c> registration parameter naming the JWE
        /// content-encryption algorithm for JARM authorization responses.</summary>
        public const string AuthorizationEncryptedResponseEnc = "authorization_encrypted_response_enc";

        /// <summary>The <c>request_object_signing_alg</c> registration parameter naming the JWS algorithm
        /// the client uses when signing Request Objects.</summary>
        public const string RequestObjectSigningAlg = "request_object_signing_alg";

        /// <summary>The <c>request_object_encryption_alg</c> registration parameter naming the JWE
        /// key-management algorithm used when encrypting Request Objects.</summary>
        public const string RequestObjectEncryptionAlg = "request_object_encryption_alg";

        /// <summary>The <c>request_object_encryption_enc</c> registration parameter naming the JWE
        /// content-encryption algorithm for Request Objects.</summary>
        public const string RequestObjectEncryptionEnc = "request_object_encryption_enc";

        /// <summary>The <c>token_endpoint_auth_method</c> registration parameter selecting the client
        /// authentication method used at the token endpoint.</summary>
        public const string TokenEndpointAuthMethod = "token_endpoint_auth_method";

        /// <summary>The <c>token_endpoint_auth_signing_alg</c> registration parameter naming the JWS
        /// algorithm used when the client authenticates with a signed JWT assertion.</summary>
        public const string TokenEndpointAuthSigningAlg = "token_endpoint_auth_signing_alg";

        /// <summary>The <c>tls_client_auth_subject_dn</c> registration parameter (RFC 8705) carrying the
        /// expected Subject Distinguished Name on the client's mTLS certificate.</summary>
        public const string TlsClientAuthSubjectDn = "tls_client_auth_subject_dn";

        /// <summary>The <c>tls_client_auth_san_dns</c> registration parameter (RFC 8705) carrying expected
        /// DNS Subject Alternative Names on the client's mTLS certificate.</summary>
        public const string TlsClientAuthSanDns = "tls_client_auth_san_dns";

        /// <summary>The <c>tls_client_auth_san_uri</c> registration parameter (RFC 8705) carrying expected
        /// URI Subject Alternative Names on the client's mTLS certificate.</summary>
        public const string TlsClientAuthSanUri = "tls_client_auth_san_uri";

        /// <summary>The <c>tls_client_auth_san_ip</c> registration parameter (RFC 8705) carrying expected
        /// IP-address Subject Alternative Names on the client's mTLS certificate.</summary>
        public const string TlsClientAuthSanIp = "tls_client_auth_san_ip";

        /// <summary>The <c>tls_client_auth_san_email</c> registration parameter (RFC 8705) carrying expected
        /// email Subject Alternative Names on the client's mTLS certificate.</summary>
        public const string TlsClientAuthSanEmail = "tls_client_auth_san_email";

        /// <summary>The <c>default_max_age</c> registration parameter specifying the default maximum
        /// authentication age (in seconds) for authorization requests from this client.</summary>
        public const string DefaultMaxAge = "default_max_age";

        /// <summary>The <c>require_auth_time</c> registration parameter; when <c>true</c>, the OP must
        /// always include the <c>auth_time</c> claim in ID Tokens for this client.</summary>
        public const string RequireAuthTime = "require_auth_time";

        /// <summary>The <c>default_acr_values</c> registration parameter listing default Authentication
        /// Context Class Reference values applied when the request omits <c>acr_values</c>.</summary>
        public const string DefaultAcrValues = "default_acr_values";

        /// <summary>The <c>initiate_login_uri</c> registration parameter pointing to a URL the OP may
        /// invoke to initiate a login flow at the client.</summary>
        public const string InitiateLoginUri = "initiate_login_uri";

        /// <summary>The <c>request_uris</c> registration parameter listing URIs the OP may pre-fetch and
        /// cache for use as <c>request_uri</c> values.</summary>
        public const string RequestUris = "request_uris";

        /// <summary>The <c>pkce_required</c> registration parameter (server extension) marking the client
        /// as PKCE-only at the authorization endpoint.</summary>
        public const string PkceRequired = "pkce_required";

        /// <summary>The <c>offline_access_allowed</c> registration parameter (server extension) controlling
        /// whether the client may request the <c>offline_access</c> scope and obtain refresh tokens.
        /// </summary>
        public const string OfflineAccessAllowed = "offline_access_allowed";

        /// <summary>The <c>dpop_bound_access_tokens</c> registration parameter (RFC 9449 §5.2) requiring
        /// DPoP-bound access tokens for this client.</summary>
        public const string DpopBoundAccessTokens = "dpop_bound_access_tokens";

        /// <summary>The <c>require_pushed_authorization_requests</c> registration parameter (RFC 9126 §6)
        /// making PAR the only way this client may start an authorization flow.</summary>
        public const string RequirePushedAuthorizationRequests = "require_pushed_authorization_requests";

        /// <summary>The <c>require_signed_request_object</c> registration parameter (RFC 9101 §10.5)
        /// committing this client to signed request objects.</summary>
        public const string RequireSignedRequestObject = "require_signed_request_object";

        /// <summary>The <c>tls_client_certificate_bound_access_tokens</c> registration parameter
        /// (RFC 8705 §3.4) requesting certificate-bound access tokens independently of the
        /// authentication method.</summary>
        public const string TlsClientCertificateBoundAccessTokens = "tls_client_certificate_bound_access_tokens";

        /// <summary>The <c>authorization_details_types</c> registration parameter (RFC 9396 §10):
        /// per-client allowlist of authorization-detail <c>type</c> values this client may use in
        /// Rich Authorization Requests.</summary>
        public const string AuthorizationDetailsTypes = "authorization_details_types";

        /// <summary>The <c>token_exchange_subject_token_types</c> registration parameter
        /// (non-standard extension; RFC 8693 does not standardise it): per-client allowlist of
        /// <c>subject_token_type</c> URIs this client may submit to the Token Exchange grant.</summary>
        public const string TokenExchangeSubjectTokenTypes = "token_exchange_subject_token_types";

        /// <summary>The <c>token_exchange_audiences</c> registration parameter
        /// (non-standard extension; RFC 8693 does not standardise it): default-deny per-client
        /// allowlist of <c>audience</c> values this client may request when exchanging a token.</summary>
        public const string TokenExchangeAudiences = "token_exchange_audiences";

        /// <summary>The <c>backchannel_logout_uri</c> registration parameter pointing to the client's
        /// back-channel logout endpoint.</summary>
        public const string BackChannelLogoutUri = "backchannel_logout_uri";

        /// <summary>The <c>backchannel_logout_session_required</c> registration parameter; when <c>true</c>,
        /// the OP must include the <c>sid</c> claim in the logout token.</summary>
        public const string BackChannelLogoutSessionRequired = "backchannel_logout_session_required";

        /// <summary>The <c>frontchannel_logout_uri</c> registration parameter pointing to the client's
        /// front-channel logout endpoint.</summary>
        public const string FrontChannelLogoutUri = "frontchannel_logout_uri";

        /// <summary>The <c>frontchannel_logout_session_required</c> registration parameter; when <c>true</c>,
        /// the OP must append <c>iss</c> and <c>sid</c> parameters to the front-channel logout URI.
        /// </summary>
        public const string FrontChannelLogoutSessionRequired = "frontchannel_logout_session_required";

        /// <summary>The <c>post_logout_redirect_uris</c> registration parameter listing absolute URIs the
        /// OP may redirect to after RP-initiated logout.</summary>
        public const string PostLogoutRedirectUris = "post_logout_redirect_uris";

        /// <summary>The <c>backchannel_token_delivery_mode</c> CIBA registration parameter selecting how
        /// tokens are delivered (poll, ping, or push).</summary>
        public const string BackChannelTokenDeliveryMode = "backchannel_token_delivery_mode";

        /// <summary>The <c>backchannel_client_notification_endpoint</c> CIBA registration parameter
        /// providing the URL at which the OP delivers ping or push notifications.</summary>
        public const string BackChannelClientNotificationEndpoint = "backchannel_client_notification_endpoint";

        /// <summary>The <c>backchannel_authentication_request_signing_alg</c> CIBA registration parameter
        /// naming the JWS algorithm used to sign backchannel authentication requests.</summary>
        public const string BackChannelAuthenticationRequestSigningAlg = "backchannel_authentication_request_signing_alg";

        /// <summary>The <c>backchannel_user_code_parameter</c> CIBA registration parameter; when <c>true</c>,
        /// the client may submit a user code with backchannel authentication requests.</summary>
        public const string BackChannelUserCodeParameter = "backchannel_user_code_parameter";

        /// <summary>The <c>scope</c> registration parameter listing scope values the client will use
        /// (space-separated per RFC 7591 §2).</summary>
        public const string Scope = "scope";

        /// <summary>The <c>software_id</c> registration parameter identifying the client software product.
        /// </summary>
        public const string SoftwareId = "software_id";

        /// <summary>The <c>software_version</c> registration parameter naming the client software version.
        /// </summary>
        public const string SoftwareVersion = "software_version";

        /// <summary>The <c>software_statement</c> registration parameter carrying a signed JWT assertion
        /// of metadata values about the client software (RFC 7591 §2.3).</summary>
        public const string SoftwareStatement = "software_statement";
    }
}
