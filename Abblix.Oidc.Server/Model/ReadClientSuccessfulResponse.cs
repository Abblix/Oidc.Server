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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents the response for a successful client read request,
/// detailing the configuration and metadata of an OAuth or OpenID Connect client.
/// </summary>
public record ReadClientSuccessfulResponse : ReadClientResponse
{
    /// <summary>
    /// The unique identifier of the client as registered with the authorization server.
    /// </summary>
    [JsonPropertyOrder(1)]
    [JsonPropertyName(Parameters.ClientId)]
    public string ClientId { get; init; } = default!;

    /// <summary>
    /// The secret associated with the client, used for authenticating with the authorization server.
    /// </summary>
    [JsonPropertyOrder(2)]
    [JsonPropertyName(Parameters.ClientSecret)]
    public string ClientSecret { get; init; } = default!;

    /// <summary>
    /// The expiration time of the client secret. Indicates when the client secret will become invalid.
    /// </summary>
    [JsonPropertyOrder(3)]
    [JsonPropertyName(Parameters.ClientSecretExpiresAt)]
    public DateTimeOffset ClientSecretExpiresAt { get; init; }

    /// <summary>
    /// The URI where client configuration information can be accessed.
    /// </summary>
    [JsonPropertyOrder(4)]
    [JsonPropertyName(Parameters.RegistrationClientUri)]
    public Uri RegistrationClientUri { get; init; } = default!;

    /// <summary>
    /// The method used for authenticating the client at the token endpoint.
    /// </summary>
    [JsonPropertyOrder(5)]
    [JsonPropertyName(Parameters.TokenEndpointAuthMethod)]
    public string TokenEndpointAuthMethod { get; init; } = default!;

    /// <summary>
    /// The type of application for which the client is registered (e.g., web, native).
    /// </summary>
    [JsonPropertyOrder(6)]
    [JsonPropertyName(Parameters.ApplicationType)]
    public string ApplicationType { get; init; } = default!;

    /// <summary>
    /// The URIs where the client expects to receive responses after user authentication.
    /// </summary>
    [JsonPropertyOrder(7)]
    [JsonPropertyName(Parameters.RedirectUris)]
    public Uri[] RedirectUris { get; init; } = default!;

    /// <summary>
    /// The name of the client.
    /// </summary>
    [JsonPropertyOrder(8)]
    [JsonPropertyName(Parameters.ClientName)]
    public string ClientName { get; init; } = default!;

    /// <summary>
    /// The name of the client.
    /// </summary>
    [JsonPropertyOrder(10)]
    [JsonPropertyName(Parameters.LogoUri)]
    [AbsoluteUri]
    public Uri LogoUri { get; init; } = default!;

    /// <summary>
    /// The type of subjects used (e.g., public, pairwise).
    /// </summary>
    [JsonPropertyOrder(11)]
    [JsonPropertyName(Parameters.SubjectType)]
    public string SubjectType { get; init; } = default!;

    /// <summary>
    /// The URI identifying the sector that the client is a part of.
    /// </summary>
    [JsonPropertyOrder(12)]
    [JsonPropertyName(Parameters.SectorIdentifierUri)]
    [AbsoluteUri]
    public Uri SectorIdentifierUri { get; init; } = default!;

    /// <summary>
    /// The URI to the client's JSON Web Key Set document.
    /// </summary>
    [JsonPropertyOrder(13)]
    [JsonPropertyName(Parameters.JwksUri)]
    public Uri JwksUri { get; init; } = default!;

    /// <summary>
    /// The algorithm used for encrypting the user information response.
    /// </summary>
    [JsonPropertyOrder(14)]
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseAlg)]
    public string UserInfoEncryptedResponseAlg { get; init; } = default!;

    /// <summary>
    /// The encryption encoding used for the user information response.
    /// </summary>
    [JsonPropertyOrder(15)]
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseEnc)]
    public string UserInfoEncryptedResponseEnc { get; init; } = default!;

    /// <summary>
    /// The contacts for the client, typically email addresses.
    /// </summary>
    [JsonPropertyOrder(16)]
    [JsonPropertyName(Parameters.Contacts)]
    public string[] Contacts { get; init; } = default!;

    /// <summary>
    /// The URIs for any request objects associated with the client.
    /// </summary>
    [JsonPropertyOrder(17)]
    [JsonPropertyName(Parameters.RequestUris)]
    public Uri[] RequestUris { get; init; } = default!;

    /// <summary>
    /// The URI for initiating the client's login process.
    /// </summary>
    [JsonPropertyOrder(18)]
    [JsonPropertyName(Parameters.InitiateLoginUri)]
    [AbsoluteUri]
    public Uri? InitiateLoginUri { get; init; }

    /// <summary>
    /// Contains constants for parameter names.
    /// </summary>
    private static class Parameters
    {
        public const string ClientId = "client_id";
        public const string ClientSecret = "client_secret";
        public const string ClientSecretExpiresAt = "client_secret_expires_at";
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
    }
}
