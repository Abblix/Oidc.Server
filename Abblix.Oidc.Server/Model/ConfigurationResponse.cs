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

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents the configuration response detailing the capabilities and endpoints of the OpenID Connect provider.
/// This response includes information about the provider's issuer identifier, key sets, supported endpoints,
/// supported features, and more, enabling clients to dynamically configure themselves to utilize the provider's
/// services.
/// </summary>
public record ConfigurationResponse
{
    /// <summary>
    /// Nested class containing string constants for JSON property names used in the configuration response.
    /// These names map directly to the fields returned by the OpenID Connect discovery document, ensuring
    /// proper serialization and deserialization of configuration data.
    /// </summary>
    public static class Parameters
    {
        public const string Issuer = "issuer";
        public const string JwksUri = "jwks_uri";
        public const string AuthorizationEndpoint = "authorization_endpoint";
        public const string TokenEndpoint = "token_endpoint";
        public const string UserInfoEndpoint = "userinfo_endpoint";
        public const string EndSessionEndpoint = "end_session_endpoint";
        public const string CheckSessionIframe = "check_session_iframe";
        public const string IntrospectionEndpoint = "introspection_endpoint";
        public const string RevocationEndpoint = "revocation_endpoint";
        public const string RegistrationEndpoint = "registration_endpoint";
        public const string FrontChannelLogoutSupported = "frontchannel_logout_supported";
        public const string FrontChannelLogoutSessionSupported = "frontchannel_logout_session_supported";
        public const string BackChannelLogoutSupported = "backchannel_logout_supported";
        public const string BackChannelLogoutSessionSupported = "backchannel_logout_session_supported";
        public const string ClaimsParameterSupported = "claims_parameter_supported";
        public const string ScopesSupported = "scopes_supported";
        public const string ClaimsSupported = "claims_supported";
        public const string GrantTypesSupported = "grant_types_supported";
        public const string ResponseTypesSupported = "response_types_supported";
        public const string ResponseModesSupported = "response_modes_supported";
        public const string TokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported";
        public const string IdTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported";
        public const string SubjectTypesSupported = "subject_types_supported";
        public const string CodeChallengeMethodsSupported = "code_challenge_methods_supported";
        public const string PromptValuesSupported = "prompt_values_supported";
        public const string RequestParameterSupported = "request_parameter_supported";
        public const string RequestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported";
        public const string UserInfoSigningAlgValuesSupported = "userinfo_signing_alg_values_supported";
        public const string PushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint";
        public const string RequirePushedAuthorizationRequests = "require_pushed_authorization_requests";
        public const string RequireSignedRequestObject = "require_signed_request_object";
        public const string BackchannelTokenDeliveryModesSupported = "backchannel_token_delivery_modes_supported";
        public const string BackchannelAuthenticationEndpoint = "backchannel_authentication_endpoint";
        public const string BackchannelAuthenticationRequestSigningAlgValuesSupported = "backchannel_authentication_request_signing_alg_values_supported";
        public const string BackchannelUserCodeParameterSupported = "backchannel_user_code_parameter_supported";
    }

    /// <summary>
    /// The issuer identifier, which uniquely identifies the OpenID Provider. This value must be used by clients
    /// when issuing requests to the provider to ensure that the request is directed to the correct entity.
    /// </summary>
    [JsonPropertyName(Parameters.Issuer)]
    public string Issuer { init; get; } = default!;

    /// <summary>
    /// The URL of the OpenID Provider's JSON Web Key Set (JWKS) document. This document contains the provider's public
    /// keys, enabling clients to verify signatures and encrypt messages to the provider.
    /// </summary>
    [JsonPropertyName(Parameters.JwksUri)]
    public Uri? JwksUri { init; get; }

    /// <summary>
    /// The URL of the authorization endpoint through which the provider handles authentication requests and user consent.
    /// </summary>
    [JsonPropertyName(Parameters.AuthorizationEndpoint)]
    public Uri? AuthorizationEndpoint { init; get; }

    /// <summary>
    /// The URL of the token endpoint where the provider issues tokens (e.g., access tokens, refresh tokens) to clients.
    /// </summary>
    [JsonPropertyName(Parameters.TokenEndpoint)]
    public Uri? TokenEndpoint { init; get; }

    /// <summary>
    /// The URL of the user information endpoint from which the provider returns claims about the authenticated user.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoEndpoint)]
    public Uri? UserInfoEndpoint { init; get; }

    /// <summary>
    /// The URL of the end session endpoint that supports logging out users from the provider.
    /// </summary>
    [JsonPropertyName(Parameters.EndSessionEndpoint)]
    public Uri? EndSessionEndpoint { init; get; }

    /// <summary>
    /// The URL of the iframe used by the provider to facilitate session management in client applications.
    /// </summary>
    [JsonPropertyName(Parameters.CheckSessionIframe)]
    public Uri? CheckSessionIframe { init; get; }

    /// <summary>
    /// The URL of the revocation endpoint where clients can revoke access tokens or refresh tokens.
    /// </summary>
    [JsonPropertyName(Parameters.RevocationEndpoint)]
    public Uri? RevocationEndpoint { init; get; }

    /// <summary>
    /// The URL of the introspection endpoint where clients can obtain information about tokens' current state.
    /// </summary>
    [JsonPropertyName(Parameters.IntrospectionEndpoint)]
    public Uri? IntrospectionEndpoint { init; get; }

    /// <summary>
    /// The URL of the client registration endpoint that supports dynamic registration of client applications.
    /// </summary>
    [JsonPropertyName(Parameters.RegistrationEndpoint)]
    public Uri? RegistrationEndpoint { init; get; }

    /// <summary>
    /// The URL for the Pushed Authorization Request endpoint, which allows clients to pre-register authorization
    /// requests.
    /// </summary>
    [JsonPropertyName(Parameters.PushedAuthorizationRequestEndpoint)]
    public Uri? PushedAuthorizationRequestEndpoint { get; set; }

    /// <summary>
    /// Indicates whether the provider requires clients to use the Pushed Authorization Requests (PAR) only.
    /// </summary>
    [JsonPropertyName(Parameters.RequirePushedAuthorizationRequests)]
    public bool? RequirePushedAuthorizationRequests { get; set; }

    /// <summary>
    /// Indicates whether the OpenID Provider supports front channel logout, allowing clients to log out users
    /// across multiple applications.
    /// </summary>
    [JsonPropertyName(Parameters.FrontChannelLogoutSupported)]
    public bool? FrontChannelLogoutSupported { init; get; }

    /// <summary>
    /// Indicates whether the OpenID Provider supports session management for front channel logout,
    /// enabling clients to be notified what user log out.
    /// </summary>
    [JsonPropertyName(Parameters.FrontChannelLogoutSessionSupported)]
    public bool? FrontChannelLogoutSessionSupported { init; get; }

    /// <summary>
    /// Indicates whether the OpenID Provider supports back channel logout, allowing clients to log out users
    /// through direct back-channel communication.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelLogoutSupported)]
    public bool? BackChannelLogoutSupported { init; get; }

    /// <summary>
    /// Indicates whether the OpenID Provider supports session management for back channel logout,
    /// enabling secure and direct notification of user logout.
    /// </summary>
    [JsonPropertyName(Parameters.BackChannelLogoutSessionSupported)]
    public bool? BackChannelLogoutSessionSupported { init; get; }

    /// <summary>
    /// Indicates whether the OpenID Provider supports the use of the claims parameter,
    /// allowing clients to request specific claims in the ID token.
    /// </summary>
    [JsonPropertyName(Parameters.ClaimsParameterSupported)]
    public bool? ClaimsParameterSupported { init; get; }

    /// <summary>
    /// Lists the scopes supported by the OpenID Provider, defining the extent of access granted by the authorization.
    /// </summary>
    [JsonPropertyName(Parameters.ScopesSupported)]
    public IEnumerable<string> ScopesSupported { init; get; } = default!;

    /// <summary>
    /// Lists the claims supported by the OpenID Provider, indicating the user information that can be included
    /// in the ID token or obtained from the UserInfo endpoint.
    /// </summary>
    [JsonPropertyName(Parameters.ClaimsSupported)]
    public IEnumerable<string> ClaimsSupported { init; get; } = default!;

    /// <summary>
    /// Lists the grant types supported by the OpenID Provider, defining the methods through which
    /// clients can request tokens.
    /// </summary>
    [JsonPropertyName(Parameters.GrantTypesSupported)]
    public IEnumerable<string> GrantTypesSupported { init; get; } = default!;

    /// <summary>
    /// Lists the response types supported by the OpenID Provider, indicating the formats that can be used
    /// for the authorization response.
    /// </summary>
    [JsonPropertyName(Parameters.ResponseTypesSupported)]
    public IEnumerable<string> ResponseTypesSupported { init; get; } = default!;

    /// <summary>
    /// Lists the response modes supported by the OpenID Provider, defining how the authorization response
    /// should be delivered to the client.
    /// </summary>
    [JsonPropertyName(Parameters.ResponseModesSupported)]
    public IEnumerable<string> ResponseModesSupported { init; get; } = default!;

    /// <summary>
    /// Lists the token endpoint authentication methods supported by the OpenID Provider,
    /// specifying how clients authenticate to the token endpoint.
    /// </summary>
    [JsonPropertyName(Parameters.TokenEndpointAuthMethodsSupported)]
    public IEnumerable<string> TokenEndpointAuthMethodsSupported { init; get; } = default!;

    /// <summary>
    /// Lists the ID token signing algorithm values supported by the OpenID Provider,
    /// indicating the algorithms that can be used to sign the ID token.
    /// </summary>
    [JsonPropertyName(Parameters.IdTokenSigningAlgValuesSupported)]
    public IEnumerable<string> IdTokenSigningAlgValuesSupported { init; get; } = default!;

    /// <summary>
    /// Lists the subject types supported by the OpenID Provider,
    /// defining how the subject's identifier is formatted and presented to the client.
    /// </summary>
    [JsonPropertyName(Parameters.SubjectTypesSupported)]
    public IEnumerable<string> SubjectTypesSupported { init; get; } = default!;

    /// <summary>
    /// Lists the code challenge methods supported by the OpenID Provider for PKCE,
    /// enhancing the security of the authorization code flow.
    /// </summary>
    [JsonPropertyName(Parameters.CodeChallengeMethodsSupported)]
    public IEnumerable<string> CodeChallengeMethodsSupported { init; get; } = default!;

    /// <summary>
    /// Indicates whether the OpenID Provider supports the use of the request parameter,
    /// enabling clients to send a fully self-contained authorization request.
    /// </summary>
    [JsonPropertyName(Parameters.RequestParameterSupported)]
    public bool RequestParameterSupported { init; get; }

    /// <summary>
    /// Lists the prompt values supported by the OpenID Provider,
    /// specifying how the provider should prompt the user during authentication.
    /// </summary>
    [JsonPropertyName(Parameters.PromptValuesSupported)]
    public IEnumerable<string> PromptValuesSupported { init; get; } = default!;

    /// <summary>
    /// Specifies the signing algorithms supported by the OpenID Provider for user information endpoints.
    /// These algorithms are used to sign the data returned from UserInfo endpoints, ensuring data integrity
    /// and authentication of the information source.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoSigningAlgValuesSupported)]
    public IEnumerable<string>? UserInfoSigningAlgValuesSupported { init; get; }

    /// <summary>
    /// Specifies the signing algorithms supported by the OpenID Provider for request objects.
    /// These algorithms are used to sign request objects sent to the OpenID Provider, providing
    /// security measures against tampering and ensuring the authenticity of the request.
    /// </summary>
    [JsonPropertyName(Parameters.RequestObjectSigningAlgValuesSupported)]
    public IEnumerable<string>? RequestObjectSigningAlgValuesSupported { init; get; }

    /// <summary>
    /// Indicates whether the OpenID Provider mandates that all request objects must be signed.
    /// This requirement ensures an additional layer of security by verifying the authenticity and
    /// integrity of request objects received by the provider.
    /// </summary>
    [JsonPropertyName(Parameters.RequireSignedRequestObject)]
    public bool? RequireSignedRequestObject { init; get; } //TODO use it!

    /// <summary>
    /// Lists the supported backchannel token delivery modes for client-initiated backchannel authentication.
    /// </summary>
    [JsonPropertyName(Parameters.BackchannelTokenDeliveryModesSupported)]
    public IEnumerable<string>? BackChannelTokenDeliveryModesSupported { get; init; }

    /// <summary>
    /// The backchannel authentication endpoint for initiating CIBA (Client-Initiated Backchannel Authentication)
    /// requests.
    /// </summary>
    [JsonPropertyName(Parameters.BackchannelAuthenticationEndpoint)]
    public Uri? BackChannelAuthenticationEndpoint { get; init; }

    /// <summary>
    /// Lists the supported signing algorithms for backchannel authentication requests.
    /// </summary>
    [JsonPropertyName(Parameters.BackchannelAuthenticationRequestSigningAlgValuesSupported)]
    public IEnumerable<string>? BackChannelAuthenticationRequestSigningAlgValuesSupported { get; init; }

    /// <summary>
    /// Indicates whether the OpenID Provider supports the backchannel user code parameter for CIBA.
    /// </summary>
    [JsonPropertyName(Parameters.BackchannelUserCodeParameterSupported)]
    public bool? BackChannelUserCodeParameterSupported { get; init; }
}
