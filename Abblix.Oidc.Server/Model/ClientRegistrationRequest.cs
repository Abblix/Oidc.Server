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

using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.DeclarativeValidation;
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
    public AuthenticationHeaderValue? AuthorizationHeader { get; set; }

    /// <summary>
    /// The <c>redirect_uris</c> array (RFC 7591 §2) listing every absolute URI the OP may use to deliver
    /// authorization responses to this client. At least one entry is required, and authorization requests
    /// must specify a redirect URI that exactly matches one of these values.
    /// </summary>
    [JsonPropertyName(Parameters.RedirectUris)]
    [ElementsRequired]
    public Uri[] RedirectUris { get; set; } = null!;

    /// <summary>
    /// The <c>response_types</c> the client intends to use (RFC 7591 §2). Each entry is itself a
    /// space-separated combination of <c>code</c>, <c>token</c>, and/or <c>id_token</c>; the array therefore
    /// represents the full set of response type combinations registered for this client.
    /// </summary>
    [JsonPropertyName(Parameters.ResponseTypes)]
    [AllowedValues(
        Common.Constants.ResponseTypes.Code,
        Common.Constants.ResponseTypes.Token,
        Common.Constants.ResponseTypes.IdToken)]
    [JsonConverter(typeof(ArrayConverter<string[], SpaceSeparatedValuesConverter>))]
    public string[][] ResponseTypes { get; init; } = [[Common.Constants.ResponseTypes.Code]];

    /// <summary>
    /// The <c>grant_types</c> the client will request at the token endpoint per RFC 7591 §2,
    /// for example <c>authorization_code</c>, <c>refresh_token</c>, or <c>urn:openid:params:grant-type:ciba</c>.
    /// </summary>
    [JsonPropertyName(Parameters.GrantTypes)]
    [AllowedValues(
        Common.Constants.GrantTypes.AuthorizationCode,
        Common.Constants.GrantTypes.Implicit,
        Common.Constants.GrantTypes.RefreshToken,
        Common.Constants.GrantTypes.Ciba)]
    public string[] GrantTypes { get; init; } = [Common.Constants.GrantTypes.AuthorizationCode];

    /// <summary>
    /// The <c>application_type</c> declared at registration (OIDC Dynamic Client Registration §2),
    /// typically <c>web</c> or <c>native</c>. Influences allowed redirect URI schemes and other policy.
    /// </summary>
    [JsonPropertyName(Parameters.ApplicationType)]
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
    public string? SubjectType { get; init; } = SubjectTypes.Public;

    /// <summary>
    /// The <c>id_token_signed_response_alg</c> (OIDC Core §2): the JWS <c>alg</c> the OP must use to sign
    /// ID Tokens issued to this client (e.g. <c>RS256</c>, <c>ES256</c>).
    /// </summary>
    [JsonPropertyName(Parameters.IdTokenSignedResponseAlg)]
    public string? IdTokenSignedResponseAlg { get; init; }

    /// <summary>
    /// The <c>id_token_encrypted_response_alg</c>: the JWE key-management algorithm the OP must use when
    /// encrypting ID Tokens for this client.
    /// </summary>
    [JsonPropertyName(Parameters.IdTokenEncryptedResponseAlg)]
    public string? IdTokenEncryptedResponseAlg { get; init; }

    /// <summary>
    /// The <c>id_token_encrypted_response_enc</c>: the JWE content-encryption algorithm paired with
    /// <see cref="IdTokenEncryptedResponseAlg"/> for ID Tokens issued to this client.
    /// </summary>
    [JsonPropertyName(Parameters.IdTokenEncryptedResponseEnc)]
    public string? IdTokenEncryptedResponseEnc { get; init; }

    /// <summary>
    /// The <c>userinfo_signed_response_alg</c>: the JWS algorithm the OP must use when signing UserInfo
    /// responses returned to this client. When omitted, UserInfo is returned as plain JSON.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoSignedResponseAlg)]
    public string? UserInfoSignedResponseAlg { get; init; }

    /// <summary>
    /// The <c>userinfo_encrypted_response_alg</c>: the JWE key-management algorithm the OP must use when
    /// encrypting UserInfo responses for this client.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseAlg)]
    public string? UserInfoEncryptedResponseAlg { get; init; }

    /// <summary>
    /// The <c>userinfo_encrypted_response_enc</c>: the JWE content-encryption algorithm paired with
    /// <see cref="UserInfoEncryptedResponseAlg"/> for UserInfo responses to this client.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseEnc)]
    public string? UserInfoEncryptedResponseEnc { get; init; }

    /// <summary>
    /// The <c>request_object_signing_alg</c>: the JWS algorithm the client uses when signing Request Objects
    /// (OIDC Core §6) sent to the authorization endpoint. <c>none</c> indicates an unsigned Request Object.
    /// </summary>
    [JsonPropertyName(Parameters.RequestObjectSigningAlg)]
    public string? RequestObjectSigningAlg { get; init; }

    /// <summary>
    /// The <c>request_object_encryption_alg</c>: the JWE key-management algorithm the client may use when
    /// encrypting Request Objects sent to the OP.
    /// </summary>
    [JsonPropertyName(Parameters.RequestObjectEncryptionAlg)]
    public string? RequestObjectEncryptionAlg { get; init; }

    /// <summary>
    /// The <c>request_object_encryption_enc</c>: the JWE content-encryption algorithm paired with
    /// <see cref="RequestObjectEncryptionAlg"/> for Request Objects.
    /// </summary>
    [JsonPropertyName(Parameters.RequestObjectEncryptionEnc)]
    public string? RequestObjectEncryptionEnc { get; init; }

    /// <summary>
    /// The <c>token_endpoint_auth_method</c> (RFC 7591 §2): the client authentication method used at the
    /// token endpoint, such as <c>client_secret_basic</c>, <c>client_secret_post</c>, <c>private_key_jwt</c>,
    /// <c>tls_client_auth</c>, or <c>none</c>.
    /// </summary>
    [JsonPropertyName(Parameters.TokenEndpointAuthMethod)]
    public string TokenEndpointAuthMethod { get; init; } = ClientAuthenticationMethods.ClientSecretBasic;

    /// <summary>
    /// The <c>token_endpoint_auth_signing_alg</c>: the JWS algorithm the client uses when signing
    /// authentication assertions for <c>private_key_jwt</c> or <c>client_secret_jwt</c> at the token endpoint.
    /// </summary>
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
    /// per RFC 7636. Server extension to RFC 7591 metadata; defaults to <c>false</c>.
    /// </summary>
    [JsonPropertyName(Parameters.PkceRequired)]
    public bool? PkceRequired { get; set; } = false;

    /// <summary>
    /// When <c>true</c>, the client is permitted to request the <c>offline_access</c> scope and receive
    /// refresh tokens. Server extension to RFC 7591 metadata; defaults to <c>true</c>.
    /// </summary>
    [JsonPropertyName(Parameters.OfflineAccessAllowed)]
    public bool? OfflineAccessAllowed { get; set; } = true;

    /// <summary>
    /// The <c>backchannel_logout_uri</c> (OIDC Back-Channel Logout 1.0): an absolute URL at the client
    /// that the OP calls server-to-server with a logout token to terminate the user's session at the client.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelLogoutUri)]
    [AbsoluteUri]
    public Uri? BackChannelLogoutUri { get; set; }

    /// <summary>
    /// The <c>backchannel_logout_session_required</c> flag: when <c>true</c>, the OP must include the
    /// <c>sid</c> claim in the back-channel logout token so the client can identify the session being ended.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelLogoutSessionRequired)]
    public bool? BackChannelLogoutSessionRequired { get; set; } = false;

    /// <summary>
    /// The <c>frontchannel_logout_uri</c> (OIDC Front-Channel Logout 1.0): an absolute URL the OP renders
    /// in an iframe inside its logout page so the client can clear its own session in the user agent.
    /// </summary>
    [JsonPropertyName(Parameters.FrontChannelLogoutUri)]
    [AbsoluteUri]
    public Uri? FrontChannelLogoutUri { get; set; }

    /// <summary>
    /// The <c>frontchannel_logout_session_required</c> flag: when <c>true</c>, the OP must append <c>iss</c>
    /// and <c>sid</c> query parameters to <see cref="FrontChannelLogoutUri"/> so the client can target the
    /// specific session being ended.
    /// </summary>
    [JsonPropertyName(Parameters.FrontChannelLogoutSessionRequired)]
    public bool? FrontChannelLogoutSessionRequired { get; set; } = false;

    /// <summary>
    /// The <c>post_logout_redirect_uris</c> (OIDC RP-Initiated Logout): the absolute URIs the OP may redirect
    /// the user agent to after RP-initiated logout. Authorization requests must specify a value that exactly
    /// matches one of these.
    /// </summary>
    [JsonPropertyName(Parameters.PostLogoutRedirectUris)]
    [ElementsRequired]
    public Uri[] PostLogoutRedirectUris { get; set; } = [];

    /// <summary>
    /// The backchannel token delivery mode to be used by this client. This determines how tokens are delivered
    /// during backchannel authentication.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelTokenDeliveryMode)]
    [AllowedValues(
        BackchannelTokenDeliveryModes.Ping,
        BackchannelTokenDeliveryModes.Poll,
        BackchannelTokenDeliveryModes.Push)]
    public string? BackChannelTokenDeliveryMode { get; set; }

    /// <summary>
    /// The endpoint where backchannel client notifications are sent for this client.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelClientNotificationEndpoint)]
    [AbsoluteUri]
    public Uri? BackChannelClientNotificationEndpoint { get; set; }

    /// <summary>
    /// The signing algorithm used for backchannel authentication requests sent to this client.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelAuthenticationRequestSigningAlg)]
    public string? BackChannelAuthenticationRequestSigningAlg { get; set; }

    /// <summary>
    /// Indicates whether the backchannel authentication process supports user codes for this client.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelUserCodeParameter)]
    public bool BackChannelUserCodeParameter { get; set; } = false;

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

    public static class Parameters
    {
        public const string RedirectUris = "redirect_uris";
        public const string ResponseTypes = "response_types";
        public const string GrantTypes = "grant_types";
        public const string ApplicationType = "application_type";
        public const string Contacts = "contacts";
        public const string ClientId = "client_id";
        public const string ClientName = "client_name";
        public const string LogoUri = "logo_uri";
        public const string ClientUri = "client_uri";
        public const string PolicyUri = "policy_uri";
        public const string TosUri = "tos_uri";
        public const string JwksUri = "jwks_uri";
        public const string Jwks = "jwks";
        public const string SectorIdentifierUri = "sector_identifier_uri";
        public const string SubjectType = "subject_type";
        public const string IdTokenSignedResponseAlg = "id_token_signed_response_alg";
        public const string IdTokenEncryptedResponseAlg = "id_token_encrypted_response_alg";
        public const string IdTokenEncryptedResponseEnc = "id_token_encrypted_response_enc";
        public const string UserInfoSignedResponseAlg = "userinfo_signed_response_alg";
        public const string UserInfoEncryptedResponseAlg = "userinfo_encrypted_response_alg";
        public const string UserInfoEncryptedResponseEnc = "userinfo_encrypted_response_enc";
        public const string RequestObjectSigningAlg = "request_object_signing_alg";
        public const string RequestObjectEncryptionAlg = "request_object_encryption_alg";
        public const string RequestObjectEncryptionEnc = "request_object_encryption_enc";
        public const string TokenEndpointAuthMethod = "token_endpoint_auth_method";
        public const string TokenEndpointAuthSigningAlg = "token_endpoint_auth_signing_alg";
        public const string TlsClientAuthSubjectDn = "tls_client_auth_subject_dn";
        public const string TlsClientAuthSanDns = "tls_client_auth_san_dns";
        public const string TlsClientAuthSanUri = "tls_client_auth_san_uri";
        public const string TlsClientAuthSanIp = "tls_client_auth_san_ip";
        public const string TlsClientAuthSanEmail = "tls_client_auth_san_email";
        public const string DefaultMaxAge = "default_max_age";
        public const string RequireAuthTime = "require_auth_time";
        public const string DefaultAcrValues = "default_acr_values";
        public const string InitiateLoginUri = "initiate_login_uri";
        public const string RequestUris = "request_uris";
        public const string PkceRequired = "pkce_required";
        public const string OfflineAccessAllowed = "offline_access_allowed";
        public const string BackChannelLogoutUri = "backchannel_logout_uri";
        public const string BackChannelLogoutSessionRequired = "backchannel_logout_session_required";
        public const string FrontChannelLogoutUri = "frontchannel_logout_uri";
        public const string FrontChannelLogoutSessionRequired = "frontchannel_logout_session_required";
        public const string PostLogoutRedirectUris = "post_logout_redirect_uris";
        public const string BackChannelTokenDeliveryMode = "backchannel_token_delivery_mode";
        public const string BackChannelClientNotificationEndpoint = "backchannel_client_notification_endpoint";
        public const string BackChannelAuthenticationRequestSigningAlg = "backchannel_authentication_request_signing_alg";
        public const string BackChannelUserCodeParameter = "backchannel_user_code_parameter";
        public const string Scope = "scope";
        public const string SoftwareId = "software_id";
        public const string SoftwareVersion = "software_version";
        public const string SoftwareStatement = "software_statement";
    }
}
