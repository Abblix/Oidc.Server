// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;
using Abblix.Utils.Json;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Parameters = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// The metadata the server holds for a registered client, as the registration, read and update responses return it:
/// RFC 7591 section 3.2.1 has the server "return all registered metadata about this client, including any fields
/// provisioned by the authorization server itself", and RFC 7592 section 3 has the read and update responses do the
/// same.
/// </summary>
/// <remarks>
/// Each member carries the name the registration request gives it, so a client compares what it sent with what it
/// reads back member by member. Built from the stored client by <see cref="Of"/>, the one place that maps one to the
/// other, so the three responses cannot return different sets.
/// </remarks>
public record RegisteredClientMetadata
{
    /// <summary>The client authentication method at the token endpoint (RFC 7591 section 2).</summary>
    [JsonPropertyOrder(100)]
    [JsonPropertyName(Parameters.TokenEndpointAuthMethod)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TokenEndpointAuthMethod { get; init; }

    /// <summary>The JWS algorithm of the client's authentication assertions (OpenID Connect Dynamic Client
    /// Registration 1.0 section 2).</summary>
    [JsonPropertyOrder(101)]
    [JsonPropertyName(Parameters.TokenEndpointAuthSigningAlg)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TokenEndpointAuthSigningAlg { get; init; }

    /// <summary>The kind of application, web or native.</summary>
    [JsonPropertyOrder(102)]
    [JsonPropertyName(Parameters.ApplicationType)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ApplicationType { get; init; }

    /// <summary>The redirection URIs (RFC 7591 section 2).</summary>
    [JsonPropertyOrder(103)]
    [JsonPropertyName(Parameters.RedirectUris)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri[]? RedirectUris { get; init; }

    /// <summary>The URIs the end user may be sent to after logout (OpenID Connect RP-Initiated Logout 1.0
    /// section 3.1).</summary>
    [JsonPropertyOrder(104)]
    [JsonPropertyName(Parameters.PostLogoutRedirectUris)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri[]? PostLogoutRedirectUris { get; init; }

    /// <summary>The grant types, the server's default included.</summary>
    [JsonPropertyOrder(105)]
    [JsonPropertyName(Parameters.GrantTypes)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? GrantTypes { get; init; }

    /// <summary>The response type combinations, each space-separated, the server's default included.</summary>
    [JsonPropertyOrder(106)]
    [JsonPropertyName(Parameters.ResponseTypes)]
    [JsonConverter(typeof(ArrayConverter<string[], SpaceSeparatedValuesConverter>))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[][]? ResponseTypes { get; init; }

    /// <summary>The scope values the client may request, serialized space-separated.</summary>
    [JsonPropertyOrder(107)]
    [JsonPropertyName(Parameters.Scope)]
    [JsonConverter(typeof(SpaceSeparatedValuesConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? Scope { get; init; }

    /// <summary>The name of the client shown to the end user.</summary>
    [JsonPropertyOrder(108)]
    [JsonPropertyName(Parameters.ClientName)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientName { get; init; }

    /// <summary>The client's home page.</summary>
    [JsonPropertyOrder(109)]
    [JsonPropertyName(Parameters.ClientUri)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? ClientUri { get; init; }

    /// <summary>The client's logo.</summary>
    [JsonPropertyOrder(110)]
    [JsonPropertyName(Parameters.LogoUri)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? LogoUri { get; init; }

    /// <summary>The client's privacy policy.</summary>
    [JsonPropertyOrder(111)]
    [JsonPropertyName(Parameters.PolicyUri)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? PolicyUri { get; init; }

    /// <summary>The client's terms of service.</summary>
    [JsonPropertyOrder(112)]
    [JsonPropertyName(Parameters.TosUri)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? TermsOfServiceUri { get; init; }

    /// <summary>The people responsible for the client.</summary>
    [JsonPropertyOrder(113)]
    [JsonPropertyName(Parameters.Contacts)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? Contacts { get; init; }

    /// <summary>The address of the client's key set.</summary>
    [JsonPropertyOrder(114)]
    [JsonPropertyName(Parameters.JwksUri)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? JwksUri { get; init; }

    /// <summary>The client's key set, registered by value.</summary>
    [JsonPropertyOrder(115)]
    [JsonPropertyName(Parameters.Jwks)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonWebKeySet? Jwks { get; init; }

    /// <summary>The kind of subject identifier the client receives, public or pairwise.</summary>
    [JsonPropertyOrder(116)]
    [JsonPropertyName(Parameters.SubjectType)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SubjectType { get; init; }

    /// <summary>The address whose host groups the client's pairwise identifiers.</summary>
    [JsonPropertyOrder(117)]
    [JsonPropertyName(Parameters.SectorIdentifierUri)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? SectorIdentifierUri { get; init; }

    /// <summary>The JWS algorithm of the client's ID tokens.</summary>
    [JsonPropertyOrder(118)]
    [JsonPropertyName(Parameters.IdTokenSignedResponseAlg)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdTokenSignedResponseAlg { get; init; }

    /// <summary>The JWE key management algorithm of the client's ID tokens.</summary>
    [JsonPropertyOrder(119)]
    [JsonPropertyName(Parameters.IdTokenEncryptedResponseAlg)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdTokenEncryptedResponseAlg { get; init; }

    /// <summary>The JWE content encryption of the client's ID tokens.</summary>
    [JsonPropertyOrder(120)]
    [JsonPropertyName(Parameters.IdTokenEncryptedResponseEnc)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdTokenEncryptedResponseEnc { get; init; }

    /// <summary>The JWS algorithm of the client's UserInfo responses, absent when they are plain JSON.</summary>
    [JsonPropertyOrder(121)]
    [JsonPropertyName(Parameters.UserInfoSignedResponseAlg)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UserInfoSignedResponseAlg { get; init; }

    /// <summary>The JWE key management algorithm of the client's UserInfo responses.</summary>
    [JsonPropertyOrder(122)]
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseAlg)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UserInfoEncryptedResponseAlg { get; init; }

    /// <summary>The JWE content encryption of the client's UserInfo responses.</summary>
    [JsonPropertyOrder(123)]
    [JsonPropertyName(Parameters.UserInfoEncryptedResponseEnc)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UserInfoEncryptedResponseEnc { get; init; }

    /// <summary>The JWS algorithm of the client's introspection responses (RFC 9701 section 6), absent when they
    /// are plain JSON.</summary>
    [JsonPropertyOrder(124)]
    [JsonPropertyName(Parameters.IntrospectionSignedResponseAlg)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IntrospectionSignedResponseAlg { get; init; }

    /// <summary>The JWE key management algorithm of the client's introspection responses.</summary>
    [JsonPropertyOrder(125)]
    [JsonPropertyName(Parameters.IntrospectionEncryptedResponseAlg)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IntrospectionEncryptedResponseAlg { get; init; }

    /// <summary>The JWE content encryption of the client's introspection responses.</summary>
    [JsonPropertyOrder(126)]
    [JsonPropertyName(Parameters.IntrospectionEncryptedResponseEnc)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IntrospectionEncryptedResponseEnc { get; init; }

    /// <summary>The JWS algorithm of the client's authorization responses (JARM).</summary>
    [JsonPropertyOrder(127)]
    [JsonPropertyName(Parameters.AuthorizationSignedResponseAlg)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AuthorizationSignedResponseAlg { get; init; }

    /// <summary>The JWE key management algorithm of the client's authorization responses (JARM).</summary>
    [JsonPropertyOrder(128)]
    [JsonPropertyName(Parameters.AuthorizationEncryptedResponseAlg)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AuthorizationEncryptedResponseAlg { get; init; }

    /// <summary>The JWE content encryption of the client's authorization responses (JARM).</summary>
    [JsonPropertyOrder(129)]
    [JsonPropertyName(Parameters.AuthorizationEncryptedResponseEnc)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AuthorizationEncryptedResponseEnc { get; init; }

    /// <summary>The JWS algorithm the client signs its request objects with.</summary>
    [JsonPropertyOrder(130)]
    [JsonPropertyName(Parameters.RequestObjectSigningAlg)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RequestObjectSigningAlg { get; init; }

    /// <summary>The JWE key management algorithm the client encrypts its request objects with.</summary>
    [JsonPropertyOrder(131)]
    [JsonPropertyName(Parameters.RequestObjectEncryptionAlg)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RequestObjectEncryptionAlg { get; init; }

    /// <summary>The JWE content encryption the client encrypts its request objects with.</summary>
    [JsonPropertyOrder(132)]
    [JsonPropertyName(Parameters.RequestObjectEncryptionEnc)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RequestObjectEncryptionEnc { get; init; }

    /// <summary>The default maximum authentication age, in seconds.</summary>
    [JsonPropertyOrder(133)]
    [JsonPropertyName(Parameters.DefaultMaxAge)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public TimeSpan? DefaultMaxAge { get; init; }

    /// <summary>Whether the client's ID tokens always carry the authentication time.</summary>
    [JsonPropertyOrder(134)]
    [JsonPropertyName(Parameters.RequireAuthTime)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? RequireAuthTime { get; init; }

    /// <summary>The default authentication context class references.</summary>
    [JsonPropertyOrder(135)]
    [JsonPropertyName(Parameters.DefaultAcrValues)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? DefaultAcrValues { get; init; }

    /// <summary>The address a third party can start a login at the client through.</summary>
    [JsonPropertyOrder(136)]
    [JsonPropertyName(Parameters.InitiateLoginUri)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? InitiateLoginUri { get; init; }

    /// <summary>The request object addresses the client registered.</summary>
    [JsonPropertyOrder(137)]
    [JsonPropertyName(Parameters.RequestUris)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri[]? RequestUris { get; init; }

    /// <summary>The client's front-channel logout address (OpenID Connect Front-Channel Logout 1.0 section 2).</summary>
    [JsonPropertyOrder(138)]
    [JsonPropertyName(Parameters.FrontChannelLogoutUri)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? FrontChannelLogoutUri { get; init; }

    /// <summary>Whether the front-channel logout address receives the issuer and session identifier.</summary>
    [JsonPropertyOrder(139)]
    [JsonPropertyName(Parameters.FrontChannelLogoutSessionRequired)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? FrontChannelLogoutSessionRequired { get; init; }

    /// <summary>The client's back-channel logout address (OpenID Connect Back-Channel Logout 1.0 section 2.2).</summary>
    [JsonPropertyOrder(140)]
    [JsonPropertyName(Parameters.BackChannelLogoutUri)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? BackChannelLogoutUri { get; init; }

    /// <summary>Whether the logout token sent to the back-channel logout address carries the session identifier.
    /// </summary>
    [JsonPropertyOrder(141)]
    [JsonPropertyName(Parameters.BackChannelLogoutSessionRequired)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? BackChannelLogoutSessionRequired { get; init; }

    /// <summary>How the client receives the outcome of a decoupled authentication (CIBA Core 1.0 section 4).
    /// </summary>
    [JsonPropertyOrder(142)]
    [JsonPropertyName(Parameters.BackChannelTokenDeliveryMode)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BackChannelTokenDeliveryMode { get; init; }

    /// <summary>The address the server notifies of a decoupled authentication's outcome.</summary>
    [JsonPropertyOrder(143)]
    [JsonPropertyName(Parameters.BackChannelClientNotificationEndpoint)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? BackChannelClientNotificationEndpoint { get; init; }

    /// <summary>The JWS algorithm the client signs its decoupled authentication requests with.</summary>
    [JsonPropertyOrder(144)]
    [JsonPropertyName(Parameters.BackChannelAuthenticationRequestSigningAlg)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BackChannelAuthenticationRequestSigningAlg { get; init; }

    /// <summary>Whether the client's decoupled authentication requests carry a user code.</summary>
    [JsonPropertyOrder(145)]
    [JsonPropertyName(Parameters.BackChannelUserCodeParameter)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? BackChannelUserCodeParameter { get; init; }

    /// <summary>The exact subject distinguished name of the client's certificate (RFC 8705 section 2.1.2).</summary>
    [JsonPropertyOrder(146)]
    [JsonPropertyName(Parameters.TlsClientAuthSubjectDn)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TlsClientAuthSubjectDn { get; init; }

    /// <summary>The DNS subject alternative names of the client's certificate.</summary>
    [JsonPropertyOrder(147)]
    [JsonPropertyName(Parameters.TlsClientAuthSanDns)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? TlsClientAuthSanDns { get; init; }

    /// <summary>The URI subject alternative names of the client's certificate.</summary>
    [JsonPropertyOrder(148)]
    [JsonPropertyName(Parameters.TlsClientAuthSanUri)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri[]? TlsClientAuthSanUri { get; init; }

    /// <summary>The IP address subject alternative names of the client's certificate.</summary>
    [JsonPropertyOrder(149)]
    [JsonPropertyName(Parameters.TlsClientAuthSanIp)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? TlsClientAuthSanIp { get; init; }

    /// <summary>The email subject alternative names of the client's certificate.</summary>
    [JsonPropertyOrder(150)]
    [JsonPropertyName(Parameters.TlsClientAuthSanEmail)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? TlsClientAuthSanEmail { get; init; }

    /// <summary>Whether access tokens are bound to the client's certificate (RFC 8705 section 3.4).</summary>
    [JsonPropertyOrder(151)]
    [JsonPropertyName(Parameters.TlsClientCertificateBoundAccessTokens)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? TlsClientCertificateBoundAccessTokens { get; init; }

    /// <summary>Whether access tokens are bound to the client's DPoP key (RFC 9449 section 5.2).</summary>
    [JsonPropertyOrder(152)]
    [JsonPropertyName(Parameters.DpopBoundAccessTokens)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? DpopBoundAccessTokens { get; init; }

    /// <summary>Whether the client starts every authorization with a pushed request (RFC 9126 section 6).</summary>
    [JsonPropertyOrder(153)]
    [JsonPropertyName(Parameters.RequirePushedAuthorizationRequests)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? RequirePushedAuthorizationRequests { get; init; }

    /// <summary>Whether the client sends its authorization parameters as a signed request object (RFC 9101
    /// section 10.5).</summary>
    [JsonPropertyOrder(154)]
    [JsonPropertyName(Parameters.RequireSignedRequestObject)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? RequireSignedRequestObject { get; init; }

    /// <summary>Whether the client uses PKCE on every authorization code request, true when it registered no
    /// choice.</summary>
    [JsonPropertyOrder(155)]
    [JsonPropertyName(Parameters.PkceRequired)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? PkceRequired { get; init; }

    /// <summary>The offline access the client receives.</summary>
    [JsonPropertyOrder(156)]
    [JsonPropertyName(Parameters.OfflineAccess)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OfflineAccess? OfflineAccess { get; init; }

    /// <summary>The authorization details types the client may request (RFC 9396 section 10).</summary>
    [JsonPropertyOrder(157)]
    [JsonPropertyName(Parameters.AuthorizationDetailsTypes)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? AuthorizationDetailsTypes { get; init; }

    /// <summary>The subject token types the client may present to token exchange (an extension of this server).
    /// </summary>
    [JsonPropertyOrder(158)]
    [JsonPropertyName(Parameters.TokenExchangeSubjectTokenTypes)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri[]? TokenExchangeSubjectTokenTypes { get; init; }

    /// <summary>The audiences the client may request in token exchange (an extension of this server).</summary>
    [JsonPropertyOrder(159)]
    [JsonPropertyName(Parameters.TokenExchangeAudiences)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? TokenExchangeAudiences { get; init; }

    /// <summary>The resources the client may get access tokens for (an extension of this server).</summary>
    [JsonPropertyOrder(162)]
    [JsonPropertyName(Parameters.AllowedResources)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri[]? AllowedResources { get; init; }

    /// <summary>The identifier of the client software (RFC 7591 section 2).</summary>
    [JsonPropertyOrder(160)]
    [JsonPropertyName(Parameters.SoftwareId)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SoftwareId { get; init; }

    /// <summary>The version of the client software (RFC 7591 section 2).</summary>
    [JsonPropertyOrder(161)]
    [JsonPropertyName(Parameters.SoftwareVersion)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SoftwareVersion { get; init; }

    /// <summary>
    /// The metadata the server holds for <paramref name="client"/>.
    /// </summary>
    /// <remarks>
    /// A signing algorithm of <c>none</c> for UserInfo and introspection responses is the server's way of storing
    /// that the response is plain JSON, which the specifications say by leaving the member out, so it is left out.
    /// </remarks>
    public static RegisteredClientMetadata Of(ClientInfo client) => WithCertificate(client.TlsClientAuth, new()
    {
        TokenEndpointAuthMethod = client.TokenEndpointAuthMethod,
        TokenEndpointAuthSigningAlg = client.TokenEndpointAuthSigningAlgorithm,
        ApplicationType = client.ApplicationType,
        RedirectUris = client.RedirectUris,
        PostLogoutRedirectUris = client.PostLogoutRedirectUris,
        GrantTypes = client.EffectiveGrantTypes,
        ResponseTypes = client.EffectiveResponseTypes,
        Scope = client.AllowedScopes,
        ClientName = client.ClientName,
        ClientUri = client.ClientUri,
        LogoUri = client.LogoUri,
        PolicyUri = client.PolicyUri,
        TermsOfServiceUri = client.TermsOfServiceUri,
        Contacts = client.Contacts,
        JwksUri = client.JwksUri,
        Jwks = client.Jwks,
        SubjectType = client.SubjectType,
        SectorIdentifierUri = client.SectorIdentifierUri,
        IdTokenSignedResponseAlg = client.IdentityTokenSignedResponseAlgorithm,
        IdTokenEncryptedResponseAlg = client.IdentityTokenEncryptedResponseAlgorithm,
        IdTokenEncryptedResponseEnc = client.IdentityTokenEncryptedResponseEncryption,
        UserInfoSignedResponseAlg = Signed(client.UserInfoSignedResponseAlgorithm),
        UserInfoEncryptedResponseAlg = client.UserInfoEncryptedResponseAlgorithm,
        UserInfoEncryptedResponseEnc = client.UserInfoEncryptedResponseEncryption,
        IntrospectionSignedResponseAlg = Signed(client.IntrospectionSignedResponseAlgorithm),
        IntrospectionEncryptedResponseAlg = client.IntrospectionEncryptedResponseAlgorithm,
        IntrospectionEncryptedResponseEnc = client.IntrospectionEncryptedResponseEncryption,
        AuthorizationSignedResponseAlg = client.AuthorizationSignedResponseAlgorithm,
        AuthorizationEncryptedResponseAlg = client.AuthorizationEncryptedResponseAlgorithm,
        AuthorizationEncryptedResponseEnc = client.AuthorizationEncryptedResponseEncryption,
        RequestObjectSigningAlg = client.RequestObjectSigningAlgorithm,
        RequestObjectEncryptionAlg = client.RequestObjectEncryptionAlgorithm,
        RequestObjectEncryptionEnc = client.RequestObjectEncryptionMethod,
        DefaultMaxAge = client.DefaultMaxAge,
        RequireAuthTime = client.RequireAuthTime,
        DefaultAcrValues = client.DefaultAcrValues,
        InitiateLoginUri = client.InitiateLoginUri,
        RequestUris = client.RequestUris,
        FrontChannelLogoutUri = client.FrontChannelLogout?.Uri,
        FrontChannelLogoutSessionRequired = client.FrontChannelLogout?.RequiresSessionId,
        BackChannelLogoutUri = client.BackChannelLogout?.Uri,
        BackChannelLogoutSessionRequired = client.BackChannelLogout?.RequiresSessionId,
        BackChannelTokenDeliveryMode = client.BackChannelTokenDeliveryMode,
        BackChannelClientNotificationEndpoint = client.BackChannelClientNotificationEndpoint,
        BackChannelAuthenticationRequestSigningAlg = client.BackChannelAuthenticationRequestSigningAlg,
        BackChannelUserCodeParameter = client.BackChannelUserCodeParameter,
        TlsClientCertificateBoundAccessTokens = client.TlsClientCertificateBoundAccessTokens,
        DpopBoundAccessTokens = client.RequireDPoP,
        RequirePushedAuthorizationRequests = client.RequirePushedAuthorizationRequests,
        RequireSignedRequestObject = client.RequireSignedRequestObject,
        PkceRequired = client.EffectivePkceRequired,
        OfflineAccess = client.OfflineAccess,
        AuthorizationDetailsTypes = client.AuthorizationDetailsTypes,
        TokenExchangeSubjectTokenTypes = client.TokenExchangeAllowedSubjectTokenTypes,
        TokenExchangeAudiences = client.TokenExchangeAllowedAudiences,
        AllowedResources = client.AllowedResources,
        SoftwareId = client.SoftwareId,
        SoftwareVersion = client.SoftwareVersion,
    });

    /// <summary>
    /// <paramref name="metadata"/> with the certificate the client authenticates with under mutual TLS, if it
    /// registered one (RFC 8705 section 2.1.2).
    /// </summary>
    private static RegisteredClientMetadata WithCertificate(
        TlsClientAuthOptions? certificate,
        RegisteredClientMetadata metadata)
    {
        if (certificate is null)
            return metadata;

        return metadata with
        {
            TlsClientAuthSubjectDn = certificate.SubjectDn,
            TlsClientAuthSanDns = certificate.SanDns,
            TlsClientAuthSanUri = certificate.SanUris,
            TlsClientAuthSanIp = certificate.SanIps,
            TlsClientAuthSanEmail = certificate.SanEmails,
        };
    }

    /// <summary>
    /// The signing algorithm a response is registered with, or null for one registered as plain JSON.
    /// </summary>
    private static string? Signed(string? algorithm) => algorithm switch
    {
        SigningAlgorithms.None => null,
        _ => algorithm,
    };
}
