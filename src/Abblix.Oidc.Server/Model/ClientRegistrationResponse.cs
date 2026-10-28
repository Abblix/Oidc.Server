// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// The response returned from the client registration endpoint per RFC 7591 section 3.2.1 and OIDC Dynamic Client
/// Registration section 3.2, echoing the registered metadata together with server-issued credentials and the URL
/// of the client configuration endpoint (RFC 7592) for subsequent management operations.
/// Unregistered metadata is omitted from the JSON per RFC 7591 section 3.2.1, not emitted as an explicit null.
/// </summary>
public record ClientRegistrationResponse : RegisteredClientMetadata
{
    /// <summary>
    /// A response carrying no metadata yet, for a serializer reading one back.
    /// </summary>
    public ClientRegistrationResponse()
    {
    }

    /// <summary>
    /// A response carrying <paramref name="metadata"/>, which the credentials are added to.
    /// </summary>
    public ClientRegistrationResponse(RegisteredClientMetadata metadata)
        : base(metadata)
    {
    }

    /// <summary>
    /// The unique Client Identifier. It must not be currently valid for any other registered client.
    /// This identifier is critical for client identification and for securing client-to-server communication.
    /// </summary>
    [Required]
    [JsonPropertyName(Parameters.ClientId)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public required string ClientId { get; init; }

    /// <summary>
    /// The client secret. This value must not be assigned to multiple clients and is used for authenticating the client with the server.
    /// </summary>
    [JsonPropertyName(Parameters.ClientSecret)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientSecret { get; init; }

    /// <summary>
    /// The registration access token that can be used at the Client Configuration Endpoint to perform subsequent operations on the client registration.
    /// </summary>
    [JsonPropertyName(Parameters.RegistrationAccessToken)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RegistrationAccessToken { get; init; }

    /// <summary>
    /// The location of the Client Configuration Endpoint where the registration access token can be used for subsequent operations.
    /// </summary>
    [JsonPropertyName(Parameters.RegistrationClientUri)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? RegistrationClientUri { get; init; }

    /// <summary>
    /// The time at which the Client Identifier was issued. Represented as the number of seconds since Unix Epoch (1970-01-01T0:0:0Z) in UTC.
    /// </summary>
    [JsonPropertyName(Parameters.ClientIdIssuedAt)]
    [JsonConverter(typeof(DateTimeOffsetUnixTimeSecondsConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
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
    /// The software statement JWT echoed back per RFC 7591 Section 3.2.1.
    /// </summary>
    [JsonPropertyName(ClientRegistrationRequest.Parameters.SoftwareStatement)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SoftwareStatement { get; init; }

    /// <summary>
    /// Wire-level member names of the client registration response (RFC 7591 section 3.2.1, RFC 7592 section 3,
    /// OIDC Dynamic Client Registration section 3.2).
    /// </summary>
    /// <remarks>
    /// Public for the same reason <see cref="ClientRegistrationRequest.Parameters"/> is: these are the member
    /// names of a published wire contract, and a consumer reading the response has to name them somehow. Left
    /// private, every caller spells the literal again, which is how a member name drifts between the server
    /// that writes it and the code that reads it.
    /// </remarks>
    public static class Parameters
    {
        /// <summary>The <c>client_id</c> response member carrying the issued client identifier.</summary>
        public const string ClientId = "client_id";

        /// <summary>The <c>client_id_issued_at</c> response member giving the issue time as Unix seconds.
        /// </summary>
        public const string ClientIdIssuedAt = "client_id_issued_at";

        /// <summary>The <c>client_secret</c> response member carrying the issued client secret.</summary>
        public const string ClientSecret = "client_secret";

        /// <summary>The <c>client_secret_expires_at</c> response member giving the secret expiration time
        /// as Unix seconds; <c>0</c> means the secret does not expire.</summary>
        public const string ClientSecretExpiresAt = "client_secret_expires_at";

        /// <summary>The <c>registration_access_token</c> response member (RFC 7592) used to authorize
        /// subsequent operations on the client configuration endpoint.</summary>
        public const string RegistrationAccessToken = "registration_access_token";

        /// <summary>The <c>registration_client_uri</c> response member (RFC 7592) locating the client
        /// configuration endpoint for this registration.</summary>
        public const string RegistrationClientUri = "registration_client_uri";

        /// <summary>The <c>initiate_login_uri</c> echoed registration metadata member.</summary>
        public const string InitiateLoginUri = "initiate_login_uri";

        /// <summary>The <c>token_endpoint_auth_method</c> echoed registration metadata member.</summary>
        public const string TokenEndpointAuthMethod = "token_endpoint_auth_method";

        /// <summary>The <c>application_type</c> echoed registration metadata member.</summary>
        public const string ApplicationType = "application_type";

        /// <summary>The <c>redirect_uris</c> echoed registration metadata member.</summary>
        public const string RedirectUris = "redirect_uris";

        /// <summary>The <c>client_name</c> echoed registration metadata member.</summary>
        public const string ClientName = "client_name";

        /// <summary>The <c>logo_uri</c> echoed registration metadata member.</summary>
        public const string LogoUri = "logo_uri";

        /// <summary>The <c>subject_type</c> echoed registration metadata member.</summary>
        public const string SubjectType = "subject_type";

        /// <summary>The <c>sector_identifier_uri</c> echoed registration metadata member.</summary>
        public const string SectorIdentifierUri = "sector_identifier_uri";

        /// <summary>The <c>jwks_uri</c> echoed registration metadata member.</summary>
        public const string JwksUri = "jwks_uri";

        /// <summary>The <c>userinfo_encrypted_response_alg</c> echoed registration metadata member.</summary>
        public const string UserInfoEncryptedResponseAlg = "userinfo_encrypted_response_alg";

        /// <summary>The <c>userinfo_encrypted_response_enc</c> echoed registration metadata member.</summary>
        public const string UserInfoEncryptedResponseEnc = "userinfo_encrypted_response_enc";

        /// <summary>The <c>introspection_signed_response_alg</c> echoed registration metadata member (RFC 9701 section 6).</summary>
        public const string IntrospectionSignedResponseAlg = "introspection_signed_response_alg";

        /// <summary>The <c>introspection_encrypted_response_alg</c> echoed registration metadata member (RFC 9701 section 6).</summary>
        public const string IntrospectionEncryptedResponseAlg = "introspection_encrypted_response_alg";

        /// <summary>The <c>introspection_encrypted_response_enc</c> echoed registration metadata member (RFC 9701 section 6).</summary>
        public const string IntrospectionEncryptedResponseEnc = "introspection_encrypted_response_enc";

        /// <summary>The <c>contacts</c> echoed registration metadata member.</summary>
        public const string Contacts = "contacts";

        /// <summary>The <c>request_uris</c> echoed registration metadata member.</summary>
        public const string RequestUris = "request_uris";

        /// <summary>The <c>tls_client_auth_subject_dn</c> echoed registration metadata member (RFC 8705).
        /// </summary>
        public const string TlsClientAuthSubjectDn = "tls_client_auth_subject_dn";

        /// <summary>The <c>tls_client_auth_san_dns</c> echoed registration metadata member (RFC 8705).
        /// </summary>
        public const string TlsClientAuthSanDns = "tls_client_auth_san_dns";

        /// <summary>The <c>tls_client_auth_san_uri</c> echoed registration metadata member (RFC 8705).
        /// </summary>
        public const string TlsClientAuthSanUri = "tls_client_auth_san_uri";

        /// <summary>The <c>tls_client_auth_san_ip</c> echoed registration metadata member (RFC 8705).
        /// </summary>
        public const string TlsClientAuthSanIp = "tls_client_auth_san_ip";

        /// <summary>The <c>tls_client_auth_san_email</c> echoed registration metadata member (RFC 8705).
        /// </summary>
        public const string TlsClientAuthSanEmail = "tls_client_auth_san_email";

        /// <summary>The <c>dpop_bound_access_tokens</c> echoed registration metadata member (RFC 9449 section 5.2).
        /// </summary>
        public const string DpopBoundAccessTokens = "dpop_bound_access_tokens";

        /// <summary>The <c>authorization_details_types</c> echoed registration metadata member
        /// (RFC 9396 section 10).</summary>
        public const string AuthorizationDetailsTypes = "authorization_details_types";

        /// <summary>The <c>token_exchange_subject_token_types</c> echoed registration metadata member
        /// (non-standard extension).</summary>
        public const string TokenExchangeSubjectTokenTypes = "token_exchange_subject_token_types";

        /// <summary>The <c>token_exchange_audiences</c> echoed registration metadata member
        /// (non-standard extension).</summary>
        public const string TokenExchangeAudiences = "token_exchange_audiences";

        /// <summary>The <c>allowed_resources</c> echoed registration metadata member (non-standard extension).
        /// </summary>
        public const string AllowedResources = "allowed_resources";
    }
}
