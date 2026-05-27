// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
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
using Abblix.Oidc.Server.DeclarativeValidation;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Represents a successful response for a client registration in the context of OpenID Connect.
/// Per RFC 7591 §3.2.1, the authorization server returns all registered metadata about the client
/// (including server-assigned defaults for omitted fields) so the client can confirm what was
/// registered without a separate read round-trip. The shape mirrors
/// <see cref="Abblix.Oidc.Server.Model.ReadClientSuccessfulResponse"/> by design — register and
/// read responses carry the same metadata surface, differing only in registration-specific timing
/// (<see cref="ClientIdIssuedAt"/>) the read endpoint does not regenerate.
/// </summary>
/// <remarks>
/// The response includes the client identifier, credentials, registration endpoint information,
/// and all registered client metadata so the client can use the registration API for subsequent
/// operations on the client configuration.
/// </remarks>
/// <param name="ClientId">
/// The unique identifier assigned to the registered client. Required per RFC 7591 §3.2.1.
/// </param>
/// <param name="ClientIdIssuedAt">
/// Time at which the client identifier was issued. Optional per RFC 7591 §3.2.1.
/// </param>
/// <param name="RegistrationAccessToken">
/// The access token for subsequent operations on the client configuration endpoint.
/// Required per RFC 7592 §3.
/// </param>
public record ClientRegistrationSuccessResponse(
    string ClientId,
    DateTimeOffset? ClientIdIssuedAt,
    string RegistrationAccessToken)
{
    /// <summary>
    /// The client secret assigned to the registered client.
    /// Optional — only present for confidential clients. Per RFC 7591 §3.2.1.
    /// </summary>
    public string? ClientSecret { get; init; }

    /// <summary>
    /// The expiration time of the client secret.
    /// Required if <c>client_secret</c> is issued. Per RFC 7591 §3.2.1.
    /// A value of 0 indicates the secret does not expire.
    /// </summary>
    public DateTimeOffset? ClientSecretExpiresAt { get; init; }

    /// <summary>
    /// The fully qualified URL of the client configuration endpoint for this client.
    /// Required per RFC 7592 §3.
    /// </summary>
    [JsonPropertyName(ResponseParameters.RegistrationClientUri)]
    public Uri? RegistrationClientUri { get; init; }

    /// <summary>
    /// The method used for authenticating the client at the token endpoint.
    /// Optional — server may assign a default. Per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(ResponseParameters.TokenEndpointAuthMethod)]
    public string? TokenEndpointAuthMethod { get; init; }

    /// <summary>
    /// The type of application for which the client is registered (e.g. <c>web</c>, <c>native</c>).
    /// Optional — server may assign a default. Per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(ResponseParameters.ApplicationType)]
    public string? ApplicationType { get; init; }

    /// <summary>
    /// The URIs where the client expects to receive responses after user authentication.
    /// Required for most grant types. Per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(ResponseParameters.RedirectUris)]
    public Uri[]? RedirectUris { get; init; }

    /// <summary>
    /// The human-readable name of the client. Optional client metadata. Per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(ResponseParameters.ClientName)]
    public string? ClientName { get; init; }

    /// <summary>
    /// URL that references a logo for the client. Optional client metadata. Per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(ResponseParameters.LogoUri)]
    [AbsoluteUri]
    public Uri? LogoUri { get; init; }

    /// <summary>
    /// The type of subject identifier used (e.g. <c>public</c>, <c>pairwise</c>).
    /// Optional — server may assign a default. Per OpenID Connect Core §8.
    /// </summary>
    [JsonPropertyName(ResponseParameters.SubjectType)]
    public string? SubjectType { get; init; }

    /// <summary>
    /// URL using the <c>https</c> scheme used in calculating pseudonymous identifiers for
    /// pairwise subject type. Optional — only relevant for pairwise. Per OpenID Connect Core §8.1.
    /// </summary>
    [JsonPropertyName(ResponseParameters.SectorIdentifierUri)]
    [AbsoluteUri]
    public Uri? SectorIdentifierUri { get; init; }

    /// <summary>
    /// URL for the client's JSON Web Key Set document.
    /// Optional — alternative to providing keys directly. Per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(ResponseParameters.JwksUri)]
    [AbsoluteUri]
    public Uri? JwksUri { get; init; }

    /// <summary>
    /// JWE <c>alg</c> algorithm for encrypting UserInfo responses.
    /// Optional. Per OpenID Connect Core §5.6.2.
    /// </summary>
    [JsonPropertyName(ResponseParameters.UserInfoEncryptedResponseAlg)]
    public string? UserInfoEncryptedResponseAlg { get; init; }

    /// <summary>
    /// JWE <c>enc</c> algorithm for encrypting UserInfo responses.
    /// Optional. Per OpenID Connect Core §5.6.2.
    /// </summary>
    [JsonPropertyName(ResponseParameters.UserInfoEncryptedResponseEnc)]
    public string? UserInfoEncryptedResponseEnc { get; init; }

    /// <summary>
    /// Array of contact email addresses for people responsible for this client.
    /// Optional client metadata. Per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(ResponseParameters.Contacts)]
    public string[]? Contacts { get; init; }

    /// <summary>
    /// Array of <c>request_uri</c> values pre-registered by the client.
    /// Optional. Per OpenID Connect Core §6.2.
    /// </summary>
    [JsonPropertyName(ResponseParameters.RequestUris)]
    public Uri[]? RequestUris { get; init; }

    /// <summary>
    /// URL the authorization server can call to initiate a login at the client.
    /// Optional. Per OpenID Connect Core §4.
    /// </summary>
    [JsonPropertyName(ResponseParameters.InitiateLoginUri)]
    [AbsoluteUri]
    public Uri? InitiateLoginUri { get; init; }

    /// <summary>
    /// Exact Subject Distinguished Name required when using <c>tls_client_auth</c> per RFC 8705.
    /// </summary>
    [JsonPropertyName(ResponseParameters.TlsClientAuthSubjectDn)]
    public string? TlsClientAuthSubjectDn { get; init; }

    /// <summary>
    /// Required DNS Subject Alternative Names for <c>tls_client_auth</c> per RFC 8705.
    /// </summary>
    [JsonPropertyName(ResponseParameters.TlsClientAuthSanDns)]
    public string[]? TlsClientAuthSanDns { get; init; }

    /// <summary>
    /// Required URI Subject Alternative Names for <c>tls_client_auth</c> per RFC 8705.
    /// </summary>
    [JsonPropertyName(ResponseParameters.TlsClientAuthSanUri)]
    public Uri[]? TlsClientAuthSanUri { get; init; }

    /// <summary>
    /// Required IP Subject Alternative Names for <c>tls_client_auth</c> per RFC 8705.
    /// </summary>
    [JsonPropertyName(ResponseParameters.TlsClientAuthSanIp)]
    public string[]? TlsClientAuthSanIp { get; init; }

    /// <summary>
    /// Required email Subject Alternative Names for <c>tls_client_auth</c> per RFC 8705.
    /// </summary>
    [JsonPropertyName(ResponseParameters.TlsClientAuthSanEmail)]
    public string[]? TlsClientAuthSanEmail { get; init; }

    /// <summary>
    /// Whether access tokens issued to this client are sender-constrained via DPoP per
    /// RFC 9449 §5.2 (<c>dpop_bound_access_tokens</c>). Echoes the registered value of
    /// <c>ClientInfo.RequireDPoP</c>.
    /// </summary>
    [JsonPropertyName(ResponseParameters.DpopBoundAccessTokens)]
    public bool? DpopBoundAccessTokens { get; init; }

    /// <summary>
    /// The per-client allowlist of authorization-detail <c>type</c> values this client may
    /// use in RFC 9396 Rich Authorization Requests (<c>authorization_details_types</c>,
    /// RFC 9396 §5.1). Echoes the registered value of
    /// <c>ClientInfo.AuthorizationDetailsTypes</c>.
    /// </summary>
    [JsonPropertyName(ResponseParameters.AuthorizationDetailsTypes)]
    public string[]? AuthorizationDetailsTypes { get; init; }

    /// <summary>
    /// Abblix extension: per-client allowlist of RFC 8693 <c>subject_token_type</c> URIs this
    /// client may submit to the Token Exchange grant. Echoes
    /// <c>ClientInfo.TokenExchangeAllowedSubjectTokenTypes</c>.
    /// </summary>
    [JsonPropertyName(ResponseParameters.TokenExchangeSubjectTokenTypes)]
    public string[]? TokenExchangeSubjectTokenTypes { get; init; }

    /// <summary>
    /// JSON property names per RFC 7591/7592, OpenID Connect Core, RFC 8705, and RFC 9449.
    /// </summary>
    private static class ResponseParameters
    {
        public const string RegistrationClientUri = "registration_client_uri";
        public const string TokenEndpointAuthMethod = "token_endpoint_auth_method";
        public const string ApplicationType = "application_type";
        public const string RedirectUris = "redirect_uris";
        public const string ClientName = "client_name";
        public const string LogoUri = "logo_uri";
        public const string SubjectType = "subject_type";
        public const string SectorIdentifierUri = "sector_identifier_uri";
        public const string JwksUri = "jwks_uri";
        public const string UserInfoEncryptedResponseAlg = "userinfo_encrypted_response_alg";
        public const string UserInfoEncryptedResponseEnc = "userinfo_encrypted_response_enc";
        public const string Contacts = "contacts";
        public const string RequestUris = "request_uris";
        public const string InitiateLoginUri = "initiate_login_uri";
        public const string TlsClientAuthSubjectDn = "tls_client_auth_subject_dn";
        public const string TlsClientAuthSanDns = "tls_client_auth_san_dns";
        public const string TlsClientAuthSanUri = "tls_client_auth_san_uri";
        public const string TlsClientAuthSanIp = "tls_client_auth_san_ip";
        public const string TlsClientAuthSanEmail = "tls_client_auth_san_email";
        public const string DpopBoundAccessTokens = "dpop_bound_access_tokens";
        public const string AuthorizationDetailsTypes = "authorization_details_types";
        public const string TokenExchangeSubjectTokenTypes = "token_exchange_subject_token_types";
    }
}
