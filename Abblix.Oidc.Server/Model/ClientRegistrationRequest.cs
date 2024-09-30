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
    /// Array of redirection URIs for the OP to redirect the End-User after getting authorization.
    /// </summary>
    [JsonPropertyName(Parameters.RedirectUris)]
    [Required]
    [ElementsRequired]
    public Uri[] RedirectUris { get; set; } = default!;

    /// <summary>
    /// List of OAuth 2.0 response_type values that the client will use.
    /// </summary>
    [JsonPropertyName(Parameters.ResponseTypes)]
    [AllowedValues(
        Common.Constants.ResponseTypes.Code,
        Common.Constants.ResponseTypes.Token,
        Common.Constants.ResponseTypes.IdToken)]
    [JsonConverter(typeof(ArrayConverter<string[], SpaceSeparatedValuesConverter>))]
    public string[][] ResponseTypes { get; init; } = { new [] { Common.Constants.ResponseTypes.Code } };

    /// <summary>
    /// List of OAuth 2.0 grant type values that the client will use.
    /// </summary>
    [JsonPropertyName(Parameters.GrantTypes)]
    [AllowedValues(
        Common.Constants.GrantTypes.AuthorizationCode,
        Common.Constants.GrantTypes.Implicit,
        Common.Constants.GrantTypes.RefreshToken)]
    public string[] GrantTypes { get; init; } = { Common.Constants.GrantTypes.AuthorizationCode };

    /// <summary>
    /// Kind of the application.
    /// </summary>
    [JsonPropertyName(Parameters.ApplicationType)]
    public string ApplicationType { get; init; } = ApplicationTypes.Web;

    /// <summary>
    /// Array of e-mail addresses of people responsible for this client.
    /// </summary>
    [JsonPropertyName(Parameters.Contacts)]
    public string[]? Contacts { get; init; }

    /// <summary>
    /// Desired identifier of the client.
    /// </summary>
    [JsonPropertyName(Parameters.ClientId)]
    public string? ClientId { get; init; }

    /// <summary>
    /// Name of the client.
    /// </summary>
    [JsonPropertyName(Parameters.ClientName)]
    public string? ClientName { get; init; }

    /// <summary>
    /// URL that references a logo for the client.
    /// </summary>
    [JsonPropertyName(Parameters.LogoUri)]
    [AbsoluteUri]
    public Uri? LogoUri { get; init; }

    /// <summary>
    /// URL of the home page of the client.
    /// </summary>
    [JsonPropertyName(Parameters.ClientUri)]
    [AbsoluteUri]
    public Uri? ClientUri { get; init; }

    /// <summary>
    /// URL that the Relying Party provides to the End-User to read about how the profile data will be used.
    /// </summary>
    [JsonPropertyName(Parameters.PolicyUri)]
    [AbsoluteUri]
    public Uri? PolicyUri { get; init; }

    /// <summary>
    /// URL that the Relying Party provides to the End-User to read about the Relying Party's terms of service.
    /// </summary>
    [JsonPropertyName(Parameters.TosUri)]
    [AbsoluteUri]
    public Uri? TermsOfServiceUri { get; init; }

    /// <summary>
    /// URL for the client's JSON Web Key Set document.
    /// </summary>
    [JsonPropertyName(Parameters.JwksUri)]
    [AbsoluteUri]
    public Uri? JwksUri { get; init; }

    /// <summary>
    /// Client's JSON Web Key Set document value.
    /// </summary>
    [JsonPropertyName(Parameters.Jwks)]
    public JsonWebKeySet? Jwks { get; init; }

    /// <summary>
    /// URL using the https scheme to be used in calculating Pseudonymous Identifiers by the OP.
    /// </summary>
    [JsonPropertyName(Parameters.SectorIdentifierUri)]
    [AbsoluteUri]
    public Uri? SectorIdentifierUri { get; init; }

    /// <summary>
    /// Subject type requested for responses to this client.
    /// </summary>
    [JsonPropertyName(Parameters.SubjectType)]
    public string? SubjectType { get; init; } = SubjectTypes.Public;

    /// <summary>
    /// JWS algorithm for the ID Token issued to this client.
    /// </summary>
    [JsonPropertyName(Parameters.IdTokenSignedResponseAlg)]
    [AllowedValues(SigningAlgorithms.None, SigningAlgorithms.RS256)]
    public string? IdTokenSignedResponseAlg { get; init; }

    /// <summary>
    /// JWE algorithm to encrypt the ID Token issued to this client.
    /// </summary>
    [JsonPropertyName(Parameters.IdTokenEncryptedResponseAlg)]
    public string? IdTokenEncryptedResponseAlg { get; init; }

    /// <summary>
    /// JWE encryption method to encrypt the ID Token issued to this client.
    /// </summary>
    [JsonPropertyName(Parameters.IdTokenEncryptedResponseEnc)]
    public string? IdTokenEncryptedResponseEnc { get; init; }

    /// <summary>
    /// JWS algorithm for UserInfo Responses.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoSignedResponseAlg)]
    [AllowedValues(SigningAlgorithms.None, SigningAlgorithms.RS256)]
    public string? UserInfoSignedResponseAlg { get; init; }

    /// <summary>
    /// JWE algorithm to encrypt UserInfo Responses.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseAlg)]
    public string? UserInfoEncryptedResponseAlg { get; init; }

    /// <summary>
    /// JWE encryption method to encrypt the UserInfo Responses.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseEnc)]
    public string? UserInfoEncryptedResponseEnc { get; init; }

    /// <summary>
    /// JWS algorithm that MUST be used for Request Objects sent to the OP.
    /// </summary>
    [JsonPropertyName(Parameters.RequestObjectSigningAlg)]
    public string? RequestObjectSigningAlg { get; init; }

    /// <summary>
    /// JWE algorithm the RP is declaring that it may use for encrypting Request Objects sent to the OP.
    /// </summary>
    [JsonPropertyName(Parameters.RequestObjectEncryptionAlg)]
    public string? RequestObjectEncryptionAlg { get; init; }

    /// <summary>
    /// JWE encryption method the RP is declaring that it may use for encrypting Request Objects sent to the OP.
    /// </summary>
    [JsonPropertyName(Parameters.RequestObjectEncryptionEnc)]
    public string? RequestObjectEncryptionEnc { get; init; }

    /// <summary>
    /// Requested Authentication Method Reference values for this client.
    /// </summary>
    [JsonPropertyName(Parameters.TokenEndpointAuthMethod)]
    [AllowedValues(
        ClientAuthenticationMethods.ClientSecretBasic,
        ClientAuthenticationMethods.ClientSecretPost,
        ClientAuthenticationMethods.PrivateKeyJwt,
        ClientAuthenticationMethods.None)]
    public string TokenEndpointAuthMethod { get; init; } = ClientAuthenticationMethods.ClientSecretBasic;

    /// <summary>
    /// JWS algorithm that MUST be used for Private Key JWT Client Authentication at the Token Endpoint.
    /// </summary>
    [JsonPropertyName(Parameters.TokenEndpointAuthSigningAlg)]
    [AllowedValues(SigningAlgorithms.None, SigningAlgorithms.RS256)]
    public string? TokenEndpointAuthSigningAlg { get; init; }

    /// <summary>
    /// Default Maximum Authentication Age in seconds.
    /// </summary>
    [JsonPropertyName(Parameters.DefaultMaxAge)]
    public TimeSpan? DefaultMaxAge { get; init; }

    /// <summary>
    /// Boolean to require the auth_time claim in the ID Token.
    /// </summary>
    [JsonPropertyName(Parameters.RequireAuthTime)]
    public bool? RequireAuthTime { get; init; }

    /// <summary>
    /// Default ACR values for this client.
    /// </summary>
    [JsonPropertyName(Parameters.DefaultAcrValues)]
    public string[]? DefaultAcrValues { get; init; }

    /// <summary>
    /// URI for the client's Initiate Login URI.
    /// </summary>
    [JsonPropertyName(Parameters.InitiateLoginUri)]
    [AbsoluteUri]
    public Uri? InitiateLoginUri { get; init; }

    /// <summary>
    /// Request parameters in the request or request_uri parameters.
    /// </summary>
    [JsonPropertyName(Parameters.RequestUris)]
    public Uri[]? RequestUris { get; init; }

    /// <summary>
    /// Gets or sets a value indicating whether PKCE (Proof Key for Code Exchange) is required.
    /// </summary>
    [JsonPropertyName(Parameters.PkceRequired)]
    public bool? PkceRequired { get; set; } = false;

    /// <summary>
    /// Gets or sets a value indicating whether offline access is allowed.
    /// </summary>
    /// <value>
    /// <c>true</c> if offline access is allowed; otherwise, <c>false</c>. Defaults to <c>true</c>.
    /// </value>
    [JsonPropertyName(Parameters.OfflineAccessAllowed)]
    public bool? OfflineAccessAllowed { get; set; } = true;

    /// <summary>
    /// Gets or sets the URI for back-channel logout.
    /// </summary>
    /// <value>
    /// The URI for the back-channel logout, or <c>null</c> if not specified.
    /// </value>
    /// <remarks>
    /// This property corresponds to the 'backchannel_logout_uri' parameter in the OpenID Connect specification.
    /// It should be an absolute URI as indicated by the <see cref="AbsoluteUriAttribute"/> attribute.
    /// </remarks>
    [JsonPropertyName(Parameters.BackChannelLogoutUri)]
    [AbsoluteUri]
    public Uri? BackChannelLogoutUri { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the back-channel logout session is required.
    /// </summary>
    /// <value>
    /// <c>true</c> if back-channel logout session is required; otherwise, <c>false</c>.
    /// </value>
    /// <remarks>
    /// This property corresponds to the 'backchannel_logout_session_required' parameter in the OpenID Connect specification.
    /// </remarks>
    [JsonPropertyName(Parameters.BackChannelLogoutSessionRequired)]
    public bool? BackChannelLogoutSessionRequired { get; set; } = false;

    /// <summary>
    /// Gets or sets the URI for front-channel logout.
    /// </summary>
    /// <value>
    /// The URI to be used for front-channel logout, or <c>null</c> if it is not specified.
    /// </value>
    /// <remarks>
    /// This property corresponds to the 'frontchannel_logout_uri' parameter in the OpenID Connect specification.
    /// It defines the URL to which the OpenID Provider will send the User Agent for logout via the front-channel.
    /// The URL should be absolute and conform to the URI standard.
    /// </remarks>
    [JsonPropertyName(Parameters.FrontChannelLogoutUri)]
    [AbsoluteUri]
    public Uri? FrontChannelLogoutUri { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the front-channel logout requires a session identifier.
    /// </summary>
    /// <value>
    /// <c>true</c> if the front-channel logout requires a session identifier; otherwise, <c>false</c>.
    /// </value>
    /// <remarks>
    /// This property corresponds to the 'frontchannel_logout_session_required' parameter in the OpenID Connect
    /// specification. When set to <c>true</c>, it indicates that the client requires a session identifier
    /// to be sent with front-channel logout requests.
    /// This is typically used to facilitate logout across multiple sessions or devices.
    /// </remarks>
    [JsonPropertyName(Parameters.FrontChannelLogoutSessionRequired)]
    public bool? FrontChannelLogoutSessionRequired { get; set; } = false;

    /// <summary>
    /// Array of URIs to which the OP will redirect the user's user agent after logging out.
    /// These URIs are used to continue the user's browsing session after logout.
    /// </summary>
    [JsonPropertyName(Parameters.PostLogoutRedirectUris)]
    [ElementsRequired]
    public Uri[] PostLogoutRedirectUris { get; set; } = Array.Empty<Uri>();

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
    }
}
