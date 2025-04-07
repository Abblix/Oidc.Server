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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.DeclarativeValidation;
using Abblix.Oidc.Server.Mvc.Binders;
using Abblix.Utils.Json;
using Microsoft.AspNetCore.Mvc;
using Core = Abblix.Oidc.Server.Model;
using Parameters = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Represents metadata for an OAuth2 client based on the OpenID Connect discovery specification.
/// This class defines the properties required for registering a client with an OpenID Connect provider.
/// </summary>
/// <remarks>
/// This follows the specification detailed at: https://openid.net/specs/openid-connect-registration-1_0.html
/// </remarks>
public record ClientRegistrationRequest
{
    /// <summary>
    /// Array of URIs to which the OpenID Provider will redirect the User Agent after getting authorization.
    /// These URIs are used in the client's authorization request and are crucial for the redirect flow in OAuth2 and
    /// OpenID Connect.
    /// </summary>
    [JsonPropertyName(Parameters.RedirectUris)]
    [ElementsRequired]
    public Uri[] RedirectUris { get; set; } = Array.Empty<Uri>();

    /// <summary>
    /// JSON array containing a list of the OAuth 2.0 response_type values.
    /// </summary>
    [JsonPropertyName(Parameters.ResponseTypes)]
    [AllowedValues(
        Common.Constants.ResponseTypes.Code,
        Common.Constants.ResponseTypes.Token,
        Common.Constants.ResponseTypes.IdToken)]
    [JsonConverter(typeof(ArrayConverter<string[], SpaceSeparatedValuesConverter>))]
    public string[][] ResponseTypes { get; init; } = { new[] { Common.Constants.ResponseTypes.Code } };

    /// <summary>
    /// Array of response type strings indicating the type of responses the client wishes to receive.
    /// </summary>
    [JsonPropertyName(Parameters.GrantTypes)]
    [AllowedValues(
        Common.Constants.GrantTypes.AuthorizationCode,
        Common.Constants.GrantTypes.Implicit,
        Common.Constants.GrantTypes.RefreshToken,
        Common.Constants.GrantTypes.Ciba)]
    public string[] GrantTypes { get; init; } = { Common.Constants.GrantTypes.AuthorizationCode };

    /// <summary>
    /// Specifies the type of the client application, such as 'web' or 'native'.
    /// This affects how the client is expected to interact with the authorization server.
    /// </summary>
    [JsonPropertyName(Parameters.ApplicationType)]
    public string ApplicationType { get; init; } = ApplicationTypes.Web;

    /// <summary>
    /// Array of email addresses of people responsible for this client.
    /// Useful for administrative contact in case of issues or updates.
    /// </summary>
    [JsonPropertyName(Parameters.Contacts)]
    public string[]? Contacts { get; init; }

    /// <summary>
    /// Custom identifier desired by the client.
    /// It is primarily used for administrative purposes and client identification.
    /// </summary>
    [JsonPropertyName(Parameters.ClientId)]
    public string? ClientId { get; init; }

    /// <summary>
    /// Name of the client application. This is used for display purposes on consent screens
    /// and in administrative interfaces.
    /// </summary>
    [JsonPropertyName(Parameters.ClientName)]
    public string? ClientName { get; init; }

    /// <summary>
    /// URL referencing the client's logo. This can be used in UIs like consent screens
    /// to represent the client application.
    /// </summary>
    [JsonPropertyName(Parameters.LogoUri)]
    [AbsoluteUri]
    public Uri? LogoUri { get; init; }

    /// <summary>
    /// URL of the client's home page. This can provide end-users with more information about the client application.
    /// </summary>
    [JsonPropertyName(Parameters.ClientUri)]
    [AbsoluteUri]
    public Uri? ClientUri { get; init; }

    /// <summary>
    /// URL to the client's privacy policy. This provides end-users with information on how their data is handled by the client.
    /// </summary>
    [JsonPropertyName(Parameters.PolicyUri)]
    [AbsoluteUri]
    public Uri? PolicyUri { get; init; }

    /// <summary>
    /// URL to the terms of service for the client. This is important for informing end-users about the terms
    /// they are agreeing to by using the client application.
    /// </summary>
    [JsonPropertyName(Parameters.TosUri)]
    [AbsoluteUri]
    public Uri? TosUri { get; init; }

    /// <summary>
    /// URL for the client's JSON Web Key Set (JWKS) document. This URI is where the OpenID Provider can retrieve
    /// the client's public keys.
    /// </summary>
    [JsonPropertyName(Parameters.JwksUri)]
    [AbsoluteUri]
    public Uri? JwksUri { get; init; }

    /// <summary>
    /// Client's JSON Web Key Set document value containing the public keys used by the client to sign requests and tokens.
    /// This is an alternative to providing a JWKS URI.
    /// </summary>
    [JsonPropertyName(Parameters.Jwks)]
    public JsonWebKeySet? Jwks { get; init; }

    /// <summary>
    /// URL using the HTTPS scheme, identifying the client's sector identifier for pairwise subject identifiers.
    /// This is used by the OpenID Provider to calculate consistent pairwise subject identifiers for the client.
    /// </summary>
    [JsonPropertyName(Parameters.SectorIdentifierUri)]
    [AbsoluteUri]
    public Uri? SectorIdentifierUri { get; init; }

    /// <summary>
    /// Subject type requested for the client's ID Tokens. This can be 'public' for shared subject identifiers
    /// or 'pairwise' for unique identifiers per client.
    /// </summary>
    [JsonPropertyName(Parameters.SubjectType)]
    public string? SubjectType { get; init; } = SubjectTypes.Public;

    /// <summary>
    /// JSON Web Signature (JWS) algorithm required for signing the ID Token issued to this client.
    /// Specifies the algorithm that the OpenID Provider should use to sign ID Tokens sent to this client.
    /// </summary>
    [JsonPropertyName(Parameters.IdTokenSignedResponseAlg)]
    public string? IdTokenSignedResponseAlg { get; init; }

    /// <summary>
    /// JSON Web Encryption (JWE) algorithm required for encrypting the ID Token issued to this client.
    /// Specifies the algorithm that must be used for encrypting ID Tokens.
    /// </summary>
    [JsonPropertyName(Parameters.IdTokenEncryptedResponseAlg)]
    public string? IdTokenEncryptedResponseAlg { get; init; }

    /// <summary>
    /// JWE encryption method required to encrypt the ID Token issued to this client.
    /// Specifies the encryption method that must be used for encrypting ID Tokens.
    /// </summary>
    [JsonPropertyName(Parameters.IdTokenEncryptedResponseEnc)]
    public string? IdTokenEncryptedResponseEnc { get; init; }

    /// <summary>
    /// JSON Web Signature (JWS) algorithm required for UserInfo Responses.
    /// Indicates the preferred algorithm for signing UserInfo responses sent to this client.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoSignedResponseAlg)]
    public string? UserInfoSignedResponseAlg { get; init; }

    /// <summary>
    /// JSON Web Encryption (JWE) algorithm required for encrypting UserInfo Responses.
    /// Specifies the algorithm that must be used for encrypting UserInfo responses sent to this client.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseAlg)]
    public string? UserInfoEncryptedResponseAlg { get; init; }

    /// <summary>
    /// JWE encryption method required for encrypting the UserInfo Responses sent to this client.
    /// Specifies the encryption method that must be used for encrypting UserInfo responses.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseEnc)]
    public string? UserInfoEncryptedResponseEnc { get; init; }

    /// <summary>
    /// JSON Web Signature (JWS) algorithm that MUST be used for Request Objects sent to the OP.
    /// Specifies the client's preferred algorithm for signing Request Objects.
    /// </summary>
    [JsonPropertyName(Parameters.RequestObjectSigningAlg)]
    public string? RequestObjectSigningAlg { get; init; }

    /// <summary>
    /// JSON Web Encryption (JWE) algorithm the RP declares it may use for encrypting Request Objects sent to the OP.
    /// Indicates the algorithm the client may use to encrypt Request Objects.
    /// </summary>
    [JsonPropertyName(Parameters.RequestObjectEncryptionAlg)]
    public string? RequestObjectEncryptionAlg { get; init; }

    /// <summary>
    /// JWE encryption method the RP declares it may use for encrypting Request Objects sent to the OP.
    /// Specifies the encryption method the client may use for encrypting Request Objects.
    /// </summary>
    [JsonPropertyName(Parameters.RequestObjectEncryptionEnc)]
    public string? RequestObjectEncryptionEnc { get; init; }

    /// <summary>
    /// Requested Authentication Method Reference values for this client.
    /// Specifies how the client will authenticate to the Token Endpoint.
    /// </summary>
    [JsonPropertyName(Parameters.TokenEndpointAuthMethod)]
    public string TokenEndpointAuthMethod { get; init; } = ClientAuthenticationMethods.ClientSecretBasic;

    /// <summary>
    /// JSON Web Signature (JWS) algorithm that MUST be used for Private Key JWT Client Authentication at the Token
    /// Endpoint. Specifies the algorithm to be used by the client for signing JWTs used in client authentication.
    /// </summary>
    [JsonPropertyName(Parameters.TokenEndpointAuthSigningAlg)]
    public string? TokenEndpointAuthSigningAlg { get; init; }

    /// <summary>
    /// Default maximum duration in seconds for which the authentication is considered valid.
    /// This value influences the expiry time of tokens issued to the client.
    /// </summary>
    [JsonPropertyName(Parameters.DefaultMaxAge)]
    [ModelBinder(typeof(SecondsToTimeSpanModelBinder))]
    public TimeSpan? DefaultMaxAge { get; init; }

    /// <summary>
    /// Boolean flag indicating whether the OpenID Provider must include the `auth_time` claim in the ID token.
    /// This is useful for clients that need to know the exact time of the user's authentication.
    /// </summary>
    [JsonPropertyName(Parameters.RequireAuthTime)]
    public bool? RequireAuthTime { get; init; }

    /// <summary>
    /// Default Authentication Context Class Reference values for this client.
    /// These values indicate the preferred level of authentication assurance for the client.
    /// </summary>
    [JsonPropertyName(Parameters.DefaultAcrValues)]
    [ModelBinder(typeof(SpaceSeparatedValuesBinder))]
    public string[]? DefaultAcrValues { get; init; }

    /// <summary>
    /// URI to initiate the login process for the client.
    /// This URI triggers the authentication flow from a third-party location.
    /// </summary>
    [JsonPropertyName(Parameters.InitiateLoginUri)]
    [AbsoluteUri]
    public Uri? InitiateLoginUri { get; init; }

    /// <summary>
    /// Array of URIs indicating where request parameters can be obtained.
    /// These URIs point to resources containing request parameters in JWT format.
    /// </summary>
    [JsonPropertyName(Parameters.RequestUris)]
    public Uri[]? RequestUris { get; init; }

    /// <summary>
    /// Indicates whether Proof Key for Code Exchange (PKCE) is required for this client.
    /// PKCE enhances the security of the OAuth authorization code flow, particularly for public clients.
    /// </summary>
    [JsonPropertyName(Parameters.PkceRequired)]
    public bool? PkceRequired { get; set; } = false;

    /// <summary>
    /// Indicates whether this client is allowed to request offline access.
    /// This typically allows the client to receive refresh tokens, enabling long-term access without user interaction.
    /// </summary>
    [JsonPropertyName(Parameters.OfflineAccessAllowed)]
    public bool OfflineAccessAllowed { get; set; } = true;

    /// <summary>
    /// Indicates whether a back-channel logout session is required for this client.
    /// This is relevant for scenarios where the client needs to be notified when the user logs out.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelLogoutSessionRequired)]
    public bool? BackChannelLogoutSessionRequired { get; set; } = false;

    /// <summary>
    /// URI used for back-channel logout. This URI is called by the OpenID Provider to initiate a logout for the client.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelLogoutUri)]
    [AbsoluteUri]
    public Uri? BackChannelLogoutUri { get; set; }

    /// <summary>
    /// URI used for front-channel logout. This URI is used to log out the user through the user agent.
    /// </summary>
    [JsonPropertyName(Parameters.FrontChannelLogoutUri)]
    [AbsoluteUri]
    public Uri? FrontChannelLogoutUri { get; set; }

    /// <summary>
    /// Indicates whether the front-channel logout requires a session identifier.
    /// This is used to manage user sessions in scenarios involving multiple clients.
    /// </summary>
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

    /// <summary>
    /// Maps the properties of this client registration request to a <see cref="Core.ClientRegistrationRequest"/>
    /// object. This method is used to translate the request data into a format that can be processed by the core
    /// registration logic.
    /// </summary>
    /// <returns>A <see cref="Core.ClientRegistrationRequest"/> object populated with data from this request.</returns>
    public Core.ClientRegistrationRequest Map()
    {
        return new Core.ClientRegistrationRequest
        {
            Contacts = Contacts,
            ClientId = ClientId,
            Jwks = Jwks,
            ResponseTypes = ResponseTypes,
            ApplicationType = ApplicationType,
            ClientName = ClientName,
            GrantTypes = GrantTypes,
            ClientUri = ClientUri,
            JwksUri = JwksUri,
            LogoUri = LogoUri,
            PkceRequired = PkceRequired,
            PolicyUri = PolicyUri,
            RedirectUris = RedirectUris,
            RequestUris = RequestUris,
            SubjectType = SubjectType,
            TermsOfServiceUri = TosUri,
            DefaultAcrValues = DefaultAcrValues,
            DefaultMaxAge = DefaultMaxAge,
            InitiateLoginUri = InitiateLoginUri,
            OfflineAccessAllowed = OfflineAccessAllowed,
            RequireAuthTime = RequireAuthTime,
            SectorIdentifierUri = SectorIdentifierUri,

            RequestObjectEncryptionAlg = RequestObjectEncryptionAlg,
            RequestObjectEncryptionEnc = RequestObjectEncryptionEnc,
            RequestObjectSigningAlg = RequestObjectSigningAlg,

            IdTokenEncryptedResponseAlg = IdTokenEncryptedResponseAlg,
            IdTokenEncryptedResponseEnc = IdTokenEncryptedResponseEnc,
            IdTokenSignedResponseAlg = IdTokenSignedResponseAlg,

            TokenEndpointAuthMethod = TokenEndpointAuthMethod,
            TokenEndpointAuthSigningAlg = TokenEndpointAuthSigningAlg,

            UserInfoEncryptedResponseAlg = UserInfoEncryptedResponseAlg,
            UserInfoEncryptedResponseEnc = UserInfoEncryptedResponseEnc,
            UserInfoSignedResponseAlg = UserInfoSignedResponseAlg,

            BackChannelLogoutUri = BackChannelLogoutUri,
            BackChannelLogoutSessionRequired = BackChannelLogoutSessionRequired,

            FrontChannelLogoutUri = FrontChannelLogoutUri,
            FrontChannelLogoutSessionRequired = FrontChannelLogoutSessionRequired,

            PostLogoutRedirectUris = PostLogoutRedirectUris,

            BackChannelTokenDeliveryMode = BackChannelTokenDeliveryMode,
            BackChannelClientNotificationEndpoint = BackChannelClientNotificationEndpoint,
            BackChannelAuthenticationRequestSigningAlg = BackChannelAuthenticationRequestSigningAlg,
            BackChannelUserCodeParameter = BackChannelUserCodeParameter,
        };
    }
}
