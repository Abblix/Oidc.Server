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

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// The response returned from the client registration endpoint per RFC 7591 §3.2.1 and OIDC Dynamic Client
/// Registration §3.2, echoing the registered metadata together with server-issued credentials and the URL
/// of the client configuration endpoint (RFC 7592) for subsequent management operations.
/// </summary>
public record ClientRegistrationResponse
{
    /// <summary>
    /// The unique Client Identifier. It must not be currently valid for any other registered client.
    /// This identifier is critical for client identification and for securing client-to-server communication.
    /// </summary>
    [Required]
    [JsonPropertyName(Parameters.ClientId)]
    public string ClientId { get; init; } = null!;

    /// <summary>
    /// The client secret. This value must not be assigned to multiple clients and is used for authenticating the client with the server.
    /// </summary>
    [JsonPropertyName(Parameters.ClientSecret)]
    public string? ClientSecret { get; init; }

    /// <summary>
    /// The registration access token that can be used at the Client Configuration Endpoint to perform subsequent operations on the client registration.
    /// </summary>
    [JsonPropertyName(Parameters.RegistrationAccessToken)]
    public string? RegistrationAccessToken { get; init; }

    /// <summary>
    /// The location of the Client Configuration Endpoint where the registration access token can be used for subsequent operations.
    /// </summary>
    [JsonPropertyName(Parameters.RegistrationClientUri)]
    public Uri? RegistrationClientUri { get; init; }

    /// <summary>
    /// The time at which the Client Identifier was issued. Represented as the number of seconds since Unix Epoch (1970-01-01T0:0:0Z) in UTC.
    /// </summary>
    [JsonPropertyName(Parameters.ClientIdIssuedAt)]
    [JsonConverter(typeof(DateTimeOffsetUnixTimeSecondsConverter))]
    public DateTimeOffset? ClientIdIssuedAt { get; init; }

    /// <summary>
    /// The time at which the client_secret will expire. Represented as the number of seconds since Unix Epoch (1970-01-01T0:0:0Z) in UTC.
    /// A value of 0 indicates that the secret does not expire.
    /// </summary>
    [Required]
    [JsonPropertyName(Parameters.ClientSecretExpiresAt)]
    [JsonConverter(typeof(DateTimeOffsetUnixTimeSecondsConverter))]
    public DateTimeOffset ClientSecretExpiresAt { get; init; }

    /// <summary>
    /// The URI for initiating the client's login process.
    /// </summary>
    [JsonPropertyName(Parameters.InitiateLoginUri)]
    public Uri? InitiateLoginUri { get; init; }

    /// <summary>
    /// The authentication method used by the client at the token endpoint.
    /// Possible values include "client_secret_basic", "client_secret_post", "client_secret_jwt",
    /// "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth", or "none".
    /// Per OpenID Connect Dynamic Client Registration Section 2.
    /// </summary>
    [JsonPropertyName(Parameters.TokenEndpointAuthMethod)]
    public string? TokenEndpointAuthMethod { get; init; }

    /// <summary>
    /// The registered scope values per RFC 7591 Section 2.
    /// </summary>
    [JsonPropertyName(ClientRegistrationRequest.Parameters.Scope)]
    [JsonConverter(typeof(SpaceSeparatedValuesConverter))]
    public string[]? Scope { get; init; }

    /// <summary>
    /// The software identifier per RFC 7591 Section 2.
    /// </summary>
    [JsonPropertyName(ClientRegistrationRequest.Parameters.SoftwareId)]
    public string? SoftwareId { get; init; }

    /// <summary>
    /// The software version per RFC 7591 Section 2.
    /// </summary>
    [JsonPropertyName(ClientRegistrationRequest.Parameters.SoftwareVersion)]
    public string? SoftwareVersion { get; init; }

    /// <summary>
    /// The software statement JWT echoed back per RFC 7591 Section 3.2.1.
    /// </summary>
    [JsonPropertyName(ClientRegistrationRequest.Parameters.SoftwareStatement)]
    public string? SoftwareStatement { get; init; }

    /// <summary>
    /// The type of application for which the client is registered (<c>web</c>, <c>native</c>).
    /// Optional — server may assign a default. Per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(Parameters.ApplicationType)]
    public string? ApplicationType { get; init; }

    /// <summary>
    /// The URIs where the client expects to receive responses after user authentication.
    /// Per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(Parameters.RedirectUris)]
    public Uri[]? RedirectUris { get; init; }

    /// <summary>
    /// The human-readable name of the client. Optional client metadata. Per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(Parameters.ClientName)]
    public string? ClientName { get; init; }

    /// <summary>
    /// URL that references a logo for the client. Optional. Per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(Parameters.LogoUri)]
    public Uri? LogoUri { get; init; }

    /// <summary>
    /// The type of subject identifier used (<c>public</c>, <c>pairwise</c>).
    /// Optional. Per OpenID Connect Core §8.
    /// </summary>
    [JsonPropertyName(Parameters.SubjectType)]
    public string? SubjectType { get; init; }

    /// <summary>
    /// URL using <c>https</c> scheme used in calculating pseudonymous identifiers for
    /// pairwise subject type. Optional. Per OpenID Connect Core §8.1.
    /// </summary>
    [JsonPropertyName(Parameters.SectorIdentifierUri)]
    public Uri? SectorIdentifierUri { get; init; }

    /// <summary>
    /// URL for the client's JSON Web Key Set document.
    /// Optional. Per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(Parameters.JwksUri)]
    public Uri? JwksUri { get; init; }

    /// <summary>
    /// JWE <c>alg</c> algorithm for encrypting UserInfo responses.
    /// Optional. Per OpenID Connect Core §5.6.2.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseAlg)]
    public string? UserInfoEncryptedResponseAlg { get; init; }

    /// <summary>
    /// JWE <c>enc</c> algorithm for encrypting UserInfo responses.
    /// Optional. Per OpenID Connect Core §5.6.2.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseEnc)]
    public string? UserInfoEncryptedResponseEnc { get; init; }

    /// <summary>
    /// Array of contact email addresses for people responsible for this client.
    /// Optional. Per RFC 7591 §2.
    /// </summary>
    [JsonPropertyName(Parameters.Contacts)]
    public string[]? Contacts { get; init; }

    /// <summary>
    /// Array of <c>request_uri</c> values pre-registered by the client.
    /// Optional. Per OpenID Connect Core §6.2.
    /// </summary>
    [JsonPropertyName(Parameters.RequestUris)]
    public Uri[]? RequestUris { get; init; }

    /// <summary>
    /// Exact Subject Distinguished Name required when using <c>tls_client_auth</c> per RFC 8705.
    /// </summary>
    [JsonPropertyName(Parameters.TlsClientAuthSubjectDn)]
    public string? TlsClientAuthSubjectDn { get; init; }

    /// <summary>
    /// Required DNS Subject Alternative Names for <c>tls_client_auth</c> per RFC 8705.
    /// </summary>
    [JsonPropertyName(Parameters.TlsClientAuthSanDns)]
    public string[]? TlsClientAuthSanDns { get; init; }

    /// <summary>
    /// Required URI Subject Alternative Names for <c>tls_client_auth</c> per RFC 8705.
    /// </summary>
    [JsonPropertyName(Parameters.TlsClientAuthSanUri)]
    public Uri[]? TlsClientAuthSanUri { get; init; }

    /// <summary>
    /// Required IP Subject Alternative Names for <c>tls_client_auth</c> per RFC 8705.
    /// </summary>
    [JsonPropertyName(Parameters.TlsClientAuthSanIp)]
    public string[]? TlsClientAuthSanIp { get; init; }

    /// <summary>
    /// Required email Subject Alternative Names for <c>tls_client_auth</c> per RFC 8705.
    /// </summary>
    [JsonPropertyName(Parameters.TlsClientAuthSanEmail)]
    public string[]? TlsClientAuthSanEmail { get; init; }

    /// <summary>
    /// Whether access tokens issued to this client are sender-constrained via DPoP per
    /// RFC 9449 §5.2 (<c>dpop_bound_access_tokens</c>). Echoes the registered value of
    /// <c>ClientInfo.RequireDPoP</c>.
    /// </summary>
    [JsonPropertyName(Parameters.DpopBoundAccessTokens)]
    public bool? DpopBoundAccessTokens { get; init; }

    private static class Parameters
    {
        public const string ClientId = "client_id";
        public const string ClientIdIssuedAt = "client_id_issued_at";

        public const string ClientSecret = "client_secret";
        public const string ClientSecretExpiresAt = "client_secret_expires_at";

        public const string RegistrationAccessToken = "registration_access_token";
        public const string RegistrationClientUri = "registration_client_uri";
        public const string InitiateLoginUri = "initiate_login_uri";
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
        public const string TlsClientAuthSubjectDn = "tls_client_auth_subject_dn";
        public const string TlsClientAuthSanDns = "tls_client_auth_san_dns";
        public const string TlsClientAuthSanUri = "tls_client_auth_san_uri";
        public const string TlsClientAuthSanIp = "tls_client_auth_san_ip";
        public const string TlsClientAuthSanEmail = "tls_client_auth_san_email";
        public const string DpopBoundAccessTokens = "dpop_bound_access_tokens";
    }
}
