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

using System.Text.Json.Serialization;
using Abblix.Oidc.Server.DeclarativeBinding;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents the response for a successful client read request,
/// detailing the configuration and metadata of an OAuth or OpenID Connect client.
/// Per RFC 7592 Section 3, this response includes the registration access token and all registered client metadata.
/// Unregistered metadata is omitted from the JSON per RFC 7592 §3, not emitted as an explicit null.
/// </summary>
[JsonIgnoreNulls]
public record ReadClientSuccessfulResponse
{
    /// <summary>
    /// The unique identifier of the client as registered with the authorization server.
    /// Required per RFC 7591 Section 3.2.1.
    /// </summary>
    [JsonPropertyOrder(1)]
    [JsonPropertyName(Parameters.ClientId)]
    public required string ClientId { get; init; }

    /// <summary>
    /// The secret associated with the client, used for authenticating with the authorization server.
    /// Optional - only present for confidential clients. Per RFC 7591 Section 3.2.1.
    /// </summary>
    [JsonPropertyOrder(2)]
    [JsonPropertyName(Parameters.ClientSecret)]
    public string? ClientSecret { get; init; }

    /// <summary>
    /// The expiration time of the client secret. Indicates when the client secret will become invalid.
    /// Required if client_secret is issued. Per RFC 7591 Section 3.2.1.
    /// A value of 0 indicates the secret does not expire.
    /// Serialized as Unix seconds (a JSON number) per RFC 7591 §3.2.1, matching the register-path DTO.
    /// </summary>
    [JsonPropertyOrder(3)]
    [JsonPropertyName(Parameters.ClientSecretExpiresAt)]
    [JsonConverter(typeof(DateTimeOffsetUnixTimeSecondsConverter))]
    public DateTimeOffset? ClientSecretExpiresAt { get; init; }

    /// <summary>
    /// The fully qualified URL of the client configuration endpoint for this client.
    /// Required per RFC 7592 Section 3.
    /// </summary>
    [JsonPropertyOrder(4)]
    [JsonPropertyName(Parameters.RegistrationClientUri)]
    public Uri? RegistrationClientUri { get; init; }

    /// <summary>
    /// The access token for subsequent operations on the client configuration endpoint.
    /// Required per RFC 7592 Section 3.
    /// </summary>
    [JsonPropertyOrder(5)]
    [JsonPropertyName(Parameters.RegistrationAccessToken)]
    public required string RegistrationAccessToken { get; init; }

    /// <summary>
    /// The method used for authenticating the client at the token endpoint.
    /// Optional - server may assign default. Per RFC 7591 Section 2.
    /// </summary>
    [JsonPropertyOrder(6)]
    [JsonPropertyName(Parameters.TokenEndpointAuthMethod)]
    public string? TokenEndpointAuthMethod { get; init; }

    /// <summary>
    /// The type of application for which the client is registered (e.g., web, native).
    /// Optional - server may assign default. Per RFC 7591 Section 2.
    /// </summary>
    [JsonPropertyOrder(7)]
    [JsonPropertyName(Parameters.ApplicationType)]
    public string? ApplicationType { get; init; }

    /// <summary>
    /// The URIs where the client expects to receive responses after user authentication.
    /// Required for most grant types. Per RFC 7591 Section 2.
    /// </summary>
    [JsonPropertyOrder(8)]
    [JsonPropertyName(Parameters.RedirectUris)]
    public required Uri[] RedirectUris { get; init; }

    /// <summary>
    /// The human-readable name of the client.
    /// Optional client metadata. Per RFC 7591 Section 2.
    /// </summary>
    [JsonPropertyOrder(9)]
    [JsonPropertyName(Parameters.ClientName)]
    public string? ClientName { get; init; }

    /// <summary>
    /// URL that references a logo for the client.
    /// Optional client metadata. Per RFC 7591 Section 2.
    /// </summary>
    [JsonPropertyOrder(10)]
    [JsonPropertyName(Parameters.LogoUri)]
    [AbsoluteUri]
    public Uri? LogoUri { get; init; }

    /// <summary>
    /// The type of subject identifier used (e.g., public, pairwise).
    /// Optional - server may assign default. Per OpenID Connect Core Section 8.
    /// </summary>
    [JsonPropertyOrder(11)]
    [JsonPropertyName(Parameters.SubjectType)]
    public string? SubjectType { get; init; }

    /// <summary>
    /// URL using the https scheme to be used in calculating pseudonymous identifiers for pairwise subject type.
    /// Optional - only relevant for pairwise subject identifiers. Per OpenID Connect Core Section 8.1.
    /// </summary>
    [JsonPropertyOrder(12)]
    [JsonPropertyName(Parameters.SectorIdentifierUri)]
    [AbsoluteUri]
    public Uri? SectorIdentifierUri { get; init; }

    /// <summary>
    /// URL for the client's JSON Web Key Set document.
    /// Optional - alternative to providing keys directly. Per RFC 7591 Section 2.
    /// </summary>
    [JsonPropertyOrder(13)]
    [JsonPropertyName(Parameters.JwksUri)]
    [AbsoluteUri]
    public Uri? JwksUri { get; init; }

    /// <summary>
    /// JWE alg algorithm for encrypting UserInfo responses.
    /// Optional. Per OpenID Connect Core Section 5.6.2.
    /// </summary>
    [JsonPropertyOrder(14)]
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseAlg)]
    public string? UserInfoEncryptedResponseAlg { get; init; }

    /// <summary>
    /// JWE enc algorithm for encrypting UserInfo responses.
    /// Optional. Per OpenID Connect Core Section 5.6.2.
    /// </summary>
    [JsonPropertyOrder(15)]
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseEnc)]
    public string? UserInfoEncryptedResponseEnc { get; init; }

    /// <summary>
    /// Array of contact email addresses for people responsible for this client.
    /// Optional client metadata. Per RFC 7591 Section 2.
    /// </summary>
    [JsonPropertyOrder(16)]
    [JsonPropertyName(Parameters.Contacts)]
    public string[]? Contacts { get; init; }

    /// <summary>
    /// Array of request_uri values that are pre-registered by the client.
    /// Optional. Per OpenID Connect Core Section 6.2.
    /// </summary>
    [JsonPropertyOrder(17)]
    [JsonPropertyName(Parameters.RequestUris)]
    public Uri[]? RequestUris { get; init; }

    /// <summary>
    /// URL that the authorization server can call to initiate a login at the client.
    /// Optional. Per OpenID Connect Core Section 4.
    /// </summary>
    [JsonPropertyOrder(18)]
    [JsonPropertyName(Parameters.InitiateLoginUri)]
    [AbsoluteUri]
    public Uri? InitiateLoginUri { get; init; }

    // --- RFC 8705 tls_client_auth metadata ---
    /// <summary>
    /// Exact Subject Distinguished Name required when using tls_client_auth.
    /// </summary>
    [JsonPropertyOrder(19)]
    [JsonPropertyName(Parameters.TlsClientAuthSubjectDn)]
    public string? TlsClientAuthSubjectDn { get; init; }

    /// <summary>
    /// Required DNS Subject Alternative Names for tls_client_auth.
    /// </summary>
    [JsonPropertyOrder(20)]
    [JsonPropertyName(Parameters.TlsClientAuthSanDns)]
    public string[]? TlsClientAuthSanDns { get; init; }

    /// <summary>
    /// Required URI Subject Alternative Names for tls_client_auth.
    /// </summary>
    [JsonPropertyOrder(21)]
    [JsonPropertyName(Parameters.TlsClientAuthSanUri)]
    public Uri[]? TlsClientAuthSanUri { get; init; }

    /// <summary>
    /// Required IP Subject Alternative Names for tls_client_auth.
    /// </summary>
    [JsonPropertyOrder(22)]
    [JsonPropertyName(Parameters.TlsClientAuthSanIp)]
    public string[]? TlsClientAuthSanIp { get; init; }

    /// <summary>
    /// Required email Subject Alternative Names for tls_client_auth.
    /// </summary>
    [JsonPropertyOrder(23)]
    [JsonPropertyName(Parameters.TlsClientAuthSanEmail)]
    public string[]? TlsClientAuthSanEmail { get; init; }

    /// <summary>
    /// Whether access tokens issued to this client are sender-constrained via DPoP per
    /// RFC 9449 §5.2 (<c>dpop_bound_access_tokens</c>). Echoes <see cref="Features.ClientInformation.ClientInfo.RequireDPoP"/>.
    /// </summary>
    [JsonPropertyOrder(24)]
    [JsonPropertyName(Parameters.DpopBoundAccessTokens)]
    public bool? DpopBoundAccessTokens { get; init; }

    /// <summary>
    /// The per-client allowlist of authorization-detail <c>type</c> values this client may
    /// use in RFC 9396 Rich Authorization Requests (<c>authorization_details_types</c>,
    /// RFC 9396 §5.1). Echoes the registered value of
    /// <see cref="Features.ClientInformation.ClientInfo.AuthorizationDetailsTypes"/>.
    /// </summary>
    [JsonPropertyOrder(25)]
    [JsonPropertyName(Parameters.AuthorizationDetailsTypes)]
    public string[]? AuthorizationDetailsTypes { get; init; }

    /// <summary>
    /// Non-standard extension: per-client allowlist of RFC 8693 <c>subject_token_type</c> URIs this
    /// client may submit to the Token Exchange grant. Echoes
    /// <see cref="Features.ClientInformation.ClientInfo.TokenExchangeAllowedSubjectTokenTypes"/>.
    /// </summary>
    [JsonPropertyOrder(26)]
    [JsonPropertyName(Parameters.TokenExchangeSubjectTokenTypes)]
    public string[]? TokenExchangeSubjectTokenTypes { get; init; }

    /// <summary>
    /// Non-standard extension: default-deny per-client allowlist of RFC 8693 <c>audience</c> values
    /// this client may request when exchanging a token. Echoes
    /// <see cref="Features.ClientInformation.ClientInfo.TokenExchangeAllowedAudiences"/>.
    /// </summary>
    [JsonPropertyOrder(27)]
    [JsonPropertyName(Parameters.TokenExchangeAudiences)]
    public string[]? TokenExchangeAudiences { get; init; }

    /// <summary>
    /// The registered grant types, including server-assigned defaults. Per RFC 7591 §2 / RFC 7592 §3.
    /// </summary>
    [JsonPropertyOrder(28)]
    [JsonPropertyName(Parameters.GrantTypes)]
    public string[]? GrantTypes { get; init; }

    /// <summary>
    /// The registered response type combinations (each entry space-separated), including
    /// server-assigned defaults. Per RFC 7591 §2 / RFC 7592 §3.
    /// </summary>
    [JsonPropertyOrder(29)]
    [JsonPropertyName(Parameters.ResponseTypes)]
    [JsonConverter(typeof(ArrayConverter<string[], SpaceSeparatedValuesConverter>))]
    public string[][]? ResponseTypes { get; init; }

    /// <summary>
    /// The registered scope values, serialized as a space-separated string.
    /// Per RFC 7591 §2 / RFC 7592 §3.
    /// </summary>
    [JsonPropertyOrder(30)]
    [JsonPropertyName(Parameters.Scope)]
    [JsonConverter(typeof(SpaceSeparatedValuesConverter))]
    public string[]? Scope { get; init; }

    /// <summary>
    /// Whether PAR is the only way this client may start an authorization flow per RFC 9126 §6.
    /// Echoes <see cref="Features.ClientInformation.ClientInfo.RequirePushedAuthorizationRequests"/>.
    /// </summary>
    [JsonPropertyOrder(31)]
    [JsonPropertyName(Parameters.RequirePushedAuthorizationRequests)]
    public bool? RequirePushedAuthorizationRequests { get; init; }

    /// <summary>
    /// Whether this client must deliver authorization parameters as a signed request object per
    /// RFC 9101 §10.5. Echoes
    /// <see cref="Features.ClientInformation.ClientInfo.RequireSignedRequestObject"/>.
    /// </summary>
    [JsonPropertyOrder(32)]
    [JsonPropertyName(Parameters.RequireSignedRequestObject)]
    public bool? RequireSignedRequestObject { get; init; }

    /// <summary>
    /// Whether access tokens are certificate-bound whenever the token request arrives over mutual
    /// TLS per RFC 8705 §3.4. Echoes
    /// <see cref="Features.ClientInformation.ClientInfo.TlsClientCertificateBoundAccessTokens"/>.
    /// </summary>
    [JsonPropertyOrder(33)]
    [JsonPropertyName(Parameters.TlsClientCertificateBoundAccessTokens)]
    public bool? TlsClientCertificateBoundAccessTokens { get; init; }

    /// <summary>
    /// Wire-level member names of the client read response (RFC 7592 §3, RFC 7591 §2/§3.2.1,
    /// and OpenID Connect Dynamic Client Registration).
    /// </summary>
    private static class Parameters
    {
        /// <summary>The <c>client_id</c> response member carrying the client identifier.</summary>
        public const string ClientId = "client_id";

        /// <summary>The <c>client_secret</c> response member carrying the client secret.</summary>
        public const string ClientSecret = "client_secret";

        /// <summary>The <c>client_secret_expires_at</c> response member giving the secret expiration time;
        /// <c>0</c> means the secret does not expire.</summary>
        public const string ClientSecretExpiresAt = "client_secret_expires_at";

        /// <summary>The <c>registration_client_uri</c> response member (RFC 7592) locating the client
        /// configuration endpoint for this registration.</summary>
        public const string RegistrationClientUri = "registration_client_uri";

        /// <summary>The <c>registration_access_token</c> response member (RFC 7592) used to authorize
        /// subsequent operations on the client configuration endpoint.</summary>
        public const string RegistrationAccessToken = "registration_access_token";

        /// <summary>The <c>token_endpoint_auth_method</c> registered metadata member.</summary>
        public const string TokenEndpointAuthMethod = "token_endpoint_auth_method";

        /// <summary>The <c>application_type</c> registered metadata member.</summary>
        public const string ApplicationType = "application_type";

        /// <summary>The <c>redirect_uris</c> registered metadata member.</summary>
        public const string RedirectUris = "redirect_uris";

        /// <summary>The <c>client_name</c> registered metadata member.</summary>
        public const string ClientName = "client_name";

        /// <summary>The <c>logo_uri</c> registered metadata member.</summary>
        public const string LogoUri = "logo_uri";

        /// <summary>The <c>subject_type</c> registered metadata member.</summary>
        public const string SubjectType = "subject_type";

        /// <summary>The <c>sector_identifier_uri</c> registered metadata member.</summary>
        public const string SectorIdentifierUri = "sector_identifier_uri";

        /// <summary>The <c>jwks_uri</c> registered metadata member.</summary>
        public const string JwksUri = "jwks_uri";

        /// <summary>The <c>userinfo_encrypted_response_alg</c> registered metadata member.</summary>
        public const string UserInfoEncryptedResponseAlg = "userinfo_encrypted_response_alg";

        /// <summary>The <c>userinfo_encrypted_response_enc</c> registered metadata member.</summary>
        public const string UserInfoEncryptedResponseEnc = "userinfo_encrypted_response_enc";

        /// <summary>The <c>contacts</c> registered metadata member.</summary>
        public const string Contacts = "contacts";

        /// <summary>The <c>request_uris</c> registered metadata member.</summary>
        public const string RequestUris = "request_uris";

        /// <summary>The <c>initiate_login_uri</c> registered metadata member.</summary>
        public const string InitiateLoginUri = "initiate_login_uri";

        /// <summary>The <c>tls_client_auth_subject_dn</c> registered metadata member (RFC 8705).</summary>
        public const string TlsClientAuthSubjectDn = "tls_client_auth_subject_dn";

        /// <summary>The <c>tls_client_auth_san_dns</c> registered metadata member (RFC 8705).</summary>
        public const string TlsClientAuthSanDns = "tls_client_auth_san_dns";

        /// <summary>The <c>tls_client_auth_san_uri</c> registered metadata member (RFC 8705).</summary>
        public const string TlsClientAuthSanUri = "tls_client_auth_san_uri";

        /// <summary>The <c>tls_client_auth_san_ip</c> registered metadata member (RFC 8705).</summary>
        public const string TlsClientAuthSanIp = "tls_client_auth_san_ip";

        /// <summary>The <c>tls_client_auth_san_email</c> registered metadata member (RFC 8705).</summary>
        public const string TlsClientAuthSanEmail = "tls_client_auth_san_email";

        /// <summary>The <c>dpop_bound_access_tokens</c> registered metadata member (RFC 9449 §5.2).
        /// </summary>
        public const string DpopBoundAccessTokens = "dpop_bound_access_tokens";

        /// <summary>The <c>authorization_details_types</c> registered metadata member (RFC 9396 §5.1).
        /// </summary>
        public const string AuthorizationDetailsTypes = "authorization_details_types";

        /// <summary>The <c>token_exchange_subject_token_types</c> registered metadata member
        /// (non-standard extension).</summary>
        public const string TokenExchangeSubjectTokenTypes = "token_exchange_subject_token_types";

        /// <summary>The <c>token_exchange_audiences</c> registered metadata member
        /// (non-standard extension).</summary>
        public const string TokenExchangeAudiences = "token_exchange_audiences";

        /// <summary>The <c>grant_types</c> registered metadata member.</summary>
        public const string GrantTypes = "grant_types";

        /// <summary>The <c>response_types</c> registered metadata member.</summary>
        public const string ResponseTypes = "response_types";

        /// <summary>The <c>scope</c> registered metadata member (space-separated).</summary>
        public const string Scope = "scope";

        /// <summary>The <c>require_pushed_authorization_requests</c> registered metadata member
        /// (RFC 9126 §6).</summary>
        public const string RequirePushedAuthorizationRequests = "require_pushed_authorization_requests";

        /// <summary>The <c>require_signed_request_object</c> registered metadata member (RFC 9101 §10.5).
        /// </summary>
        public const string RequireSignedRequestObject = "require_signed_request_object";

        /// <summary>The <c>tls_client_certificate_bound_access_tokens</c> registered metadata member
        /// (RFC 8705 §3.4).</summary>
        public const string TlsClientCertificateBoundAccessTokens = "tls_client_certificate_bound_access_tokens";
    }
}
