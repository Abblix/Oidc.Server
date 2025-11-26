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
using Abblix.Oidc.Server.DeclarativeValidation;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents the response for a successful client read request,
/// detailing the configuration and metadata of an OAuth or OpenID Connect client.
/// Per RFC 7592 Section 3, this response includes the registration access token and all registered client metadata.
/// </summary>
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
    /// </summary>
    [JsonPropertyOrder(3)]
    [JsonPropertyName(Parameters.ClientSecretExpiresAt)]
    public DateTimeOffset? ClientSecretExpiresAt { get; init; }

    /// <summary>
    /// The fully qualified URL of the client configuration endpoint for this client.
    /// Required per RFC 7592 Section 3.
    /// </summary>
    [JsonPropertyOrder(4)]
    [JsonPropertyName(Parameters.RegistrationClientUri)]
    public required Uri RegistrationClientUri { get; init; }

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
    /// Contains constants for parameter names per RFC 7591/7592 and OpenID Connect specifications.
    /// </summary>
    private static class Parameters
    {
        public const string ClientId = "client_id";
        public const string ClientSecret = "client_secret";
        public const string ClientSecretExpiresAt = "client_secret_expires_at";
        public const string RegistrationClientUri = "registration_client_uri";
        public const string RegistrationAccessToken = "registration_access_token";
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
        // RFC 8705 tls_client_auth metadata
        public const string TlsClientAuthSubjectDn = "tls_client_auth_subject_dn";
        public const string TlsClientAuthSanDns = "tls_client_auth_san_dns";
        public const string TlsClientAuthSanUri = "tls_client_auth_san_uri";
        public const string TlsClientAuthSanIp = "tls_client_auth_san_ip";
        public const string TlsClientAuthSanEmail = "tls_client_auth_san_email";
    }
}
