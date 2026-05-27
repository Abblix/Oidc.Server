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

using Abblix.Utils.Json;
using System.Text.Json.Serialization;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// The OpenID Provider discovery document returned by the <c>/.well-known/openid-configuration</c> endpoint,
/// as defined by OpenID Connect Discovery 1.0 §3 and OAuth 2.0 Authorization Server Metadata (RFC 8414).
/// Its content lists the provider's endpoints, supported algorithms, response types, scopes, and feature flags
/// so that relying parties can configure themselves dynamically.
/// </summary>
/// <remarks>
/// Decorated with <see cref="JsonIgnoreNullsAttribute"/> so that all nullable optional properties are omitted
/// from the serialized JSON when <c>null</c>, rather than emitted as <c>"field": null</c>.
/// RFC 8414 §2 requires that optional metadata fields be absent when not applicable — some OIDC client libraries
/// (including <c>Microsoft.IdentityModel</c>) reject a discovery document that contains <c>null</c> values for
/// fields they do not expect to be present.
/// </remarks>
[JsonIgnoreNulls]
public record ConfigurationResponse
{
    /// <summary>
    /// Nested class containing string constants for JSON property names used in the configuration response.
    /// These names map directly to the fields returned by the OpenID Connect discovery document, ensuring
    /// proper serialization and deserialization of configuration data.
    /// </summary>
    public static class Parameters
    {
        /// <summary>The <c>issuer</c> metadata field carrying the OpenID Provider's issuer identifier.
        /// </summary>
        public const string Issuer = "issuer";

        /// <summary>The <c>jwks_uri</c> metadata field pointing to the provider's JSON Web Key Set.
        /// </summary>
        public const string JwksUri = "jwks_uri";

        /// <summary>The <c>authorization_endpoint</c> metadata field pointing to the authorization endpoint.
        /// </summary>
        public const string AuthorizationEndpoint = "authorization_endpoint";

        /// <summary>The <c>token_endpoint</c> metadata field pointing to the token endpoint.</summary>
        public const string TokenEndpoint = "token_endpoint";

        /// <summary>The <c>userinfo_endpoint</c> metadata field pointing to the UserInfo endpoint.
        /// </summary>
        public const string UserInfoEndpoint = "userinfo_endpoint";

        /// <summary>The <c>end_session_endpoint</c> metadata field pointing to the RP-initiated logout
        /// endpoint.</summary>
        public const string EndSessionEndpoint = "end_session_endpoint";

        /// <summary>The <c>check_session_iframe</c> metadata field pointing to the OP iframe used for
        /// OpenID Connect Session Management 1.0.</summary>
        public const string CheckSessionIframe = "check_session_iframe";

        /// <summary>The <c>introspection_endpoint</c> metadata field pointing to the token introspection
        /// endpoint (RFC 7662).</summary>
        public const string IntrospectionEndpoint = "introspection_endpoint";

        /// <summary>The <c>revocation_endpoint</c> metadata field pointing to the token revocation
        /// endpoint (RFC 7009).</summary>
        public const string RevocationEndpoint = "revocation_endpoint";

        /// <summary>The <c>registration_endpoint</c> metadata field pointing to the dynamic client
        /// registration endpoint (RFC 7591).</summary>
        public const string RegistrationEndpoint = "registration_endpoint";

        /// <summary>The <c>frontchannel_logout_supported</c> metadata flag advertising front-channel
        /// logout support (OIDC Front-Channel Logout 1.0).</summary>
        public const string FrontChannelLogoutSupported = "frontchannel_logout_supported";

        /// <summary>The <c>frontchannel_logout_session_supported</c> metadata flag advertising
        /// front-channel logout session identifier support.</summary>
        public const string FrontChannelLogoutSessionSupported = "frontchannel_logout_session_supported";

        /// <summary>The <c>backchannel_logout_supported</c> metadata flag advertising back-channel
        /// logout support (OIDC Back-Channel Logout 1.0).</summary>
        public const string BackChannelLogoutSupported = "backchannel_logout_supported";

        /// <summary>The <c>backchannel_logout_session_supported</c> metadata flag advertising
        /// back-channel logout session identifier support.</summary>
        public const string BackChannelLogoutSessionSupported = "backchannel_logout_session_supported";

        /// <summary>The <c>claims_parameter_supported</c> metadata flag advertising support for the
        /// <c>claims</c> request parameter.</summary>
        public const string ClaimsParameterSupported = "claims_parameter_supported";

        /// <summary>The <c>scopes_supported</c> metadata field listing scope values the provider
        /// recognises.</summary>
        public const string ScopesSupported = "scopes_supported";

        /// <summary>The <c>claims_supported</c> metadata field listing claim names the provider may
        /// emit.</summary>
        public const string ClaimsSupported = "claims_supported";

        /// <summary>The <c>grant_types_supported</c> metadata field listing grant types the provider
        /// accepts at the token endpoint.</summary>
        public const string GrantTypesSupported = "grant_types_supported";

        /// <summary>The <c>response_types_supported</c> metadata field listing response type combinations
        /// the authorization endpoint accepts.</summary>
        public const string ResponseTypesSupported = "response_types_supported";

        /// <summary>The <c>response_modes_supported</c> metadata field listing response modes the
        /// authorization endpoint supports.</summary>
        public const string ResponseModesSupported = "response_modes_supported";

        /// <summary>The <c>token_endpoint_auth_methods_supported</c> metadata field listing client
        /// authentication methods accepted at the token endpoint.</summary>
        public const string TokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported";

        /// <summary>The <c>token_endpoint_auth_signing_alg_values_supported</c> metadata field listing
        /// JWS algorithms accepted on client authentication assertions.</summary>
        public const string TokenEndpointAuthSigningAlgValuesSupported = "token_endpoint_auth_signing_alg_values_supported";

        /// <summary>The <c>id_token_signing_alg_values_supported</c> metadata field listing JWS algorithms
        /// the provider uses to sign ID Tokens.</summary>
        public const string IdTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported";

        /// <summary>The <c>subject_types_supported</c> metadata field listing subject identifier types
        /// the provider can issue (<c>public</c>, <c>pairwise</c>).</summary>
        public const string SubjectTypesSupported = "subject_types_supported";

        /// <summary>The <c>code_challenge_methods_supported</c> metadata field listing PKCE code-challenge
        /// methods the provider accepts (RFC 7636).</summary>
        public const string CodeChallengeMethodsSupported = "code_challenge_methods_supported";

        /// <summary>The <c>prompt_values_supported</c> metadata field listing valid <c>prompt</c> parameter
        /// values.</summary>
        public const string PromptValuesSupported = "prompt_values_supported";

        /// <summary>The <c>request_parameter_supported</c> metadata flag advertising support for the
        /// <c>request</c> request object parameter.</summary>
        public const string RequestParameterSupported = "request_parameter_supported";

        /// <summary>The <c>request_object_signing_alg_values_supported</c> metadata field listing JWS
        /// algorithms accepted on Request Objects.</summary>
        public const string RequestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported";

        /// <summary>The <c>userinfo_signing_alg_values_supported</c> metadata field listing JWS algorithms
        /// the provider may use when signing UserInfo responses.</summary>
        public const string UserInfoSigningAlgValuesSupported = "userinfo_signing_alg_values_supported";

        /// <summary>The <c>dpop_signing_alg_values_supported</c> metadata field listing JWS algorithms
        /// accepted on DPoP proofs (RFC 9449 §5.1).</summary>
        public const string DpopSigningAlgValuesSupported = "dpop_signing_alg_values_supported";

        /// <summary>The <c>pushed_authorization_request_endpoint</c> metadata field pointing to the PAR
        /// endpoint (RFC 9126).</summary>
        public const string PushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint";

        /// <summary>The <c>require_pushed_authorization_requests</c> metadata flag indicating PAR is
        /// mandatory at the authorization endpoint (RFC 9126).</summary>
        public const string RequirePushedAuthorizationRequests = "require_pushed_authorization_requests";

        /// <summary>The <c>require_signed_request_object</c> metadata flag indicating signed Request
        /// Objects are mandatory.</summary>
        public const string RequireSignedRequestObject = "require_signed_request_object";

        /// <summary>The <c>backchannel_token_delivery_modes_supported</c> metadata field listing CIBA
        /// token delivery modes (<c>poll</c>, <c>ping</c>, <c>push</c>).</summary>
        public const string BackchannelTokenDeliveryModesSupported = "backchannel_token_delivery_modes_supported";

        /// <summary>The <c>backchannel_authentication_endpoint</c> metadata field pointing to the CIBA
        /// backchannel authentication endpoint.</summary>
        public const string BackchannelAuthenticationEndpoint = "backchannel_authentication_endpoint";

        /// <summary>The <c>backchannel_authentication_request_signing_alg_values_supported</c> metadata
        /// field listing JWS algorithms accepted on signed CIBA requests.</summary>
        public const string BackchannelAuthenticationRequestSigningAlgValuesSupported = "backchannel_authentication_request_signing_alg_values_supported";

        /// <summary>The <c>backchannel_user_code_parameter_supported</c> metadata flag advertising the
        /// CIBA <c>user_code</c> parameter.</summary>
        public const string BackchannelUserCodeParameterSupported = "backchannel_user_code_parameter_supported";

        /// <summary>The <c>device_authorization_endpoint</c> metadata field pointing to the Device
        /// Authorization Grant endpoint (RFC 8628).</summary>
        public const string DeviceAuthorizationEndpoint = "device_authorization_endpoint";

        /// <summary>The <c>mtls_endpoint_aliases</c> metadata block carrying mTLS-bound alternative
        /// endpoint URLs (RFC 8705 §5).</summary>
        public const string MtlsEndpointAliases = "mtls_endpoint_aliases";

        /// <summary>The <c>acr_values_supported</c> metadata field listing Authentication Context Class
        /// Reference values the provider can satisfy.</summary>
        public const string AcrValuesSupported = "acr_values_supported";

        /// <summary>The <c>authorization_response_iss_parameter_supported</c> metadata flag advertising
        /// inclusion of the <c>iss</c> parameter in authorization responses (RFC 9207).</summary>
        public const string AuthorizationResponseIssParameterSupported = "authorization_response_iss_parameter_supported";

        /// <summary>The <c>signed_metadata</c> field carrying a JWS whose claims duplicate this
        /// metadata, signed by the provider so clients can verify its origin (RFC 8414 §2.1).
        /// </summary>
        public const string SignedMetadata = "signed_metadata";

        /// <summary>The <c>authorization_details_types_supported</c> metadata field listing the
        /// authorization-detail <c>type</c> values this server understands (RFC 9396 §13).
        /// Absent when no per-type validators are registered.</summary>
        public const string AuthorizationDetailsTypesSupported = "authorization_details_types_supported";
    }

    /// <summary>
    /// The issuer identifier, which uniquely identifies the OpenID Provider. This value must be used by clients
    /// when issuing requests to the provider to ensure that the request is directed to the correct entity.
    /// </summary>
    [JsonPropertyName(Parameters.Issuer)]
    public string Issuer { init; get; } = null!;

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
    public IEnumerable<string> ScopesSupported { init; get; } = null!;

    /// <summary>
    /// Lists the claims supported by the OpenID Provider, indicating the user information that can be included
    /// in the ID token or obtained from the UserInfo endpoint.
    /// </summary>
    [JsonPropertyName(Parameters.ClaimsSupported)]
    public IEnumerable<string> ClaimsSupported { init; get; } = null!;

    /// <summary>
    /// Lists the grant types supported by the OpenID Provider, defining the methods through which
    /// clients can request tokens.
    /// </summary>
    [JsonPropertyName(Parameters.GrantTypesSupported)]
    public IEnumerable<string> GrantTypesSupported { init; get; } = null!;

    /// <summary>
    /// Lists the response types supported by the OpenID Provider, indicating the formats that can be used
    /// for the authorization response.
    /// </summary>
    [JsonPropertyName(Parameters.ResponseTypesSupported)]
    public IEnumerable<string> ResponseTypesSupported { init; get; } = null!;

    /// <summary>
    /// Lists the response modes supported by the OpenID Provider, defining how the authorization response
    /// should be delivered to the client.
    /// </summary>
    [JsonPropertyName(Parameters.ResponseModesSupported)]
    public IEnumerable<string> ResponseModesSupported { init; get; } = null!;

    /// <summary>
    /// Lists the token endpoint authentication methods supported by the OpenID Provider,
    /// specifying how clients authenticate to the token endpoint.
    /// </summary>
    [JsonPropertyName(Parameters.TokenEndpointAuthMethodsSupported)]
    public IEnumerable<string> TokenEndpointAuthMethodsSupported { init; get; } = null!;

    /// <summary>
    /// Lists the signing algorithms supported by the OpenID Provider for authenticating clients at the token endpoint.
    /// These algorithms are used to verify the signatures of the authentication requests sent to the token endpoint,
    /// ensuring the integrity and authenticity of the requests.
    /// </summary>
    [JsonPropertyName(Parameters.TokenEndpointAuthSigningAlgValuesSupported)]
    public IEnumerable<string>? TokenEndpointAuthSigningAlgValuesSupported { get; init; }

    /// <summary>
    /// Lists the ID token signing algorithm values supported by the OpenID Provider,
    /// indicating the algorithms that can be used to sign the ID token.
    /// </summary>
    [JsonPropertyName(Parameters.IdTokenSigningAlgValuesSupported)]
    public IEnumerable<string> IdTokenSigningAlgValuesSupported { init; get; } = null!;

    /// <summary>
    /// Lists the subject types supported by the OpenID Provider,
    /// defining how the subject's identifier is formatted and presented to the client.
    /// </summary>
    [JsonPropertyName(Parameters.SubjectTypesSupported)]
    public IEnumerable<string> SubjectTypesSupported { init; get; } = null!;

    /// <summary>
    /// Lists the code challenge methods supported by the OpenID Provider for PKCE,
    /// enhancing the security of the authorization code flow.
    /// </summary>
    [JsonPropertyName(Parameters.CodeChallengeMethodsSupported)]
    public IEnumerable<string> CodeChallengeMethodsSupported { init; get; } = null!;

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
    public IEnumerable<string> PromptValuesSupported { init; get; } = null!;

    /// <summary>
    /// Specifies the signing algorithms supported by the OpenID Provider for user information endpoints.
    /// These algorithms are used to sign the data returned from UserInfo endpoints, ensuring data integrity
    /// and authentication of the information source.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfoSigningAlgValuesSupported)]
    public IEnumerable<string>? UserInfoSigningAlgValuesSupported { init; get; }

    /// <summary>
    /// JWS signing algorithms accepted on inbound DPoP proofs per RFC 9449 §5.1
    /// (<c>dpop_signing_alg_values_supported</c>).
    /// </summary>
    [JsonPropertyName(Parameters.DpopSigningAlgValuesSupported)]
    public IEnumerable<string>? DpopSigningAlgValuesSupported { init; get; }

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
    public bool? RequireSignedRequestObject { init; get; }

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

    /// <summary>
    /// The URL of the device authorization endpoint as defined in RFC 8628.
    /// This endpoint is used to initiate the Device Authorization Grant flow.
    /// </summary>
    [JsonPropertyName(Parameters.DeviceAuthorizationEndpoint)]
    public Uri? DeviceAuthorizationEndpoint { get; init; }

    /// <summary>
    /// RFC 8705: mTLS endpoint aliases block to advertise alternate endpoints served on an mTLS-bound host.
    /// </summary>
    [JsonPropertyName(Parameters.MtlsEndpointAliases)]
    public MtlsAliases? MtlsEndpointAliases { get; init; }

    /// <summary>
    /// Lists the ACR (Authentication Context Class Reference) values supported by the OpenID Provider.
    /// These values represent authentication assurance levels that can be requested and achieved.
    /// </summary>
    [JsonPropertyName(Parameters.AcrValuesSupported)]
    public IEnumerable<string>? AcrValuesSupported { get; init; }

    /// <summary>
    /// Indicates that the server includes the <c>iss</c> parameter in every authorization response per RFC 9207.
    /// Clients that inspect this flag activate mix-up attack defenses.
    /// </summary>
    [JsonPropertyName(Parameters.AuthorizationResponseIssParameterSupported)]
    public bool? AuthorizationResponseIssParameterSupported { get; init; }

    /// <summary>
    /// RFC 8414 §2.1: a JWS whose payload restates this entire metadata set, signed with the
    /// provider's signing key. When present, a client that verifies the signature against the
    /// keys at <see cref="JwksUri"/> may trust the configuration's origin beyond the TLS layer;
    /// signed values take precedence over the corresponding plain-JSON fields. Emitted only
    /// when <c>DiscoveryOptions.SignedMetadata</c> is enabled, and computed last so the signed
    /// payload never contains this field itself.
    /// </summary>
    [JsonPropertyName(Parameters.SignedMetadata)]
    public string? SignedMetadata { get; init; }

    /// <summary>
    /// RFC 9396 §13: the authorization-detail <c>type</c> values this server's host has
    /// registered validators for. The list is projected from the keyed-DI registry of
    /// <see cref="Features.AuthorizationDetails.IAuthorizationDetailValidator"/> so it always
    /// matches what request-time dispatch will accept. Omitted from the emitted discovery
    /// JSON when the list is empty (no per-type validators registered) so the document
    /// follows the OIDC discovery convention: absent = unsupported, not the empty array.
    /// </summary>
    [JsonPropertyName(Parameters.AuthorizationDetailsTypesSupported)]
    public IEnumerable<string>? AuthorizationDetailsTypesSupported { get; init; }
}
