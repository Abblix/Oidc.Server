// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Model;

/// <summary>
/// The metadata the registration, read and update responses return is every value the server stores for the
/// client (RFC 7591 section 3.2.1, RFC 7592 section 3).
/// </summary>
/// <remarks>
/// The client is built from a registration request by the builder the server stores registrations through, so a
/// value the builder drops or a mapping that reads the wrong stored member fails here. Every member carries a value
/// of its own, apart from the server's default and from every other member.
/// </remarks>
public class RegisteredClientMetadataTests
{
    /// <summary>
    /// The two request members that are not client metadata: the identifier the server assigns, and a software
    /// statement the server reads and does not keep, which the registration response returns from the request.
    /// </summary>
    private static readonly string[] NotMetadata =
        [ClientRegistrationRequest.Parameters.ClientId, ClientRegistrationRequest.Parameters.SoftwareStatement];

    /// <summary>
    /// Every member the registration request accepts comes back under the same name, so a member added to the
    /// request without one in the response fails here rather than going missing on the wire.
    /// </summary>
    [Fact]
    public void EveryRequestMember_HasAResponseMemberOfTheSameName()
    {
        var missing = WireNames(typeof(ClientRegistrationRequest))
            .Except(NotMetadata)
            .Except(WireNames(typeof(RegisteredClientMetadata)))
            .ToArray();

        Assert.Empty(missing);
    }

    /// <summary>
    /// Every member of a request with every member set comes back with the value the request carried.
    /// </summary>
    [Fact]
    public void EveryRegisteredValue_ComesBackAsSent()
    {
        var request = FullRequest();
        var sent = JsonSerializer.SerializeToNode(request)!.AsObject();

        var returned = JsonSerializer.SerializeToNode(RegisteredClientMetadata.Of(Registered(request)))!.AsObject();

        var differing = WireNames(typeof(ClientRegistrationRequest))
            .Except(NotMetadata)
            .Where(name => sent[name] is null || !JsonNode.DeepEquals(sent[name], returned[name]))
            .Select(name => $"{name}: sent {sent[name]?.ToJsonString()}, got {returned[name]?.ToJsonString()}")
            .ToArray();

        Assert.Empty(differing);
    }

    /// <summary>
    /// A UserInfo or introspection response registered as plain JSON is stored with the <c>none</c> algorithm and
    /// returned the way the specifications say it: with the member left out.
    /// </summary>
    [Fact]
    public void APlainJsonResponse_LeavesItsSigningAlgorithmOut()
    {
        var request = FullRequest() with
        {
            UserInfoSignedResponseAlg = SigningAlgorithms.None,
            IntrospectionSignedResponseAlg = SigningAlgorithms.None,
        };

        var metadata = RegisteredClientMetadata.Of(Registered(request));

        Assert.Null(metadata.UserInfoSignedResponseAlg);
        Assert.Null(metadata.IntrospectionSignedResponseAlg);
    }

    /// <summary>
    /// A client registering no PKCE choice is returned the choice the server applies to it.
    /// </summary>
    [Fact]
    public void NoPkceChoice_ReturnsTheOneApplied()
    {
        var metadata = RegisteredClientMetadata.Of(Registered(FullRequest() with { PkceRequired = null }));

        Assert.True(metadata.PkceRequired);
    }

    /// <summary>
    /// A client registering no certificate returns none of the certificate members.
    /// </summary>
    [Fact]
    public void AClientWithoutACertificate_ReturnsNoCertificateMembers()
    {
        var request = FullRequest() with
        {
            TlsClientAuthSubjectDn = null,
            TlsClientAuthSanDns = null,
            TlsClientAuthSanUri = null,
            TlsClientAuthSanIp = null,
            TlsClientAuthSanEmail = null,
        };

        var metadata = RegisteredClientMetadata.Of(Registered(request));

        Assert.Null(metadata.TlsClientAuthSubjectDn);
        Assert.Null(metadata.TlsClientAuthSanDns);
        Assert.Null(metadata.TlsClientAuthSanUri);
        Assert.Null(metadata.TlsClientAuthSanIp);
        Assert.Null(metadata.TlsClientAuthSanEmail);
    }

    private static string[] WireNames(Type type)
        => type
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(property => property.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name)
            .OfType<string>()
            .ToArray();

    /// <summary>
    /// The client the server stores for <paramref name="request"/>, its sector the host of the registered sector
    /// identifier URI, as the registration validators derive it.
    /// </summary>
    private static ClientInfo Registered(ClientRegistrationRequest request)
        => new ClientInfoBuilder("client", request)
            .WithSectorIdentifier(request.SectorIdentifierUri?.Host)
            .Build();

    private static ClientRegistrationRequest FullRequest() => new()
    {
        RedirectUris = [new Uri("https://client.example.com/callback")],
        PostLogoutRedirectUris = [new Uri("https://client.example.com/signed-out")],
        GrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken, GrantTypes.Ciba],
        ResponseTypes = [[ResponseTypes.Code]],
        Scope = [Scopes.OpenId, Scopes.Profile],
        ApplicationType = ApplicationTypes.Native,
        Contacts = ["ops@client.example.com"],
        ClientName = "Client",
        ClientUri = new Uri("https://client.example.com/"),
        LogoUri = new Uri("https://client.example.com/logo.png"),
        PolicyUri = new Uri("https://client.example.com/privacy"),
        TermsOfServiceUri = new Uri("https://client.example.com/terms"),
        JwksUri = new Uri("https://client.example.com/jwks"),
        Jwks = new JsonWebKeySet([new RsaJsonWebKey { KeyId = "client-key", Modulus = [1, 2, 3], Exponent = [1, 0, 1] }]),
        SectorIdentifierUri = new Uri("https://sector.example.com/sector.json"),
        SubjectType = SubjectTypes.Pairwise,
        TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
        TokenEndpointAuthSigningAlg = SigningAlgorithms.PS256,
        IdTokenSignedResponseAlg = SigningAlgorithms.ES256,
        IdTokenEncryptedResponseAlg = EncryptionAlgorithms.KeyManagement.RsaOaep256,
        IdTokenEncryptedResponseEnc = EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
        UserInfoSignedResponseAlg = SigningAlgorithms.ES384,
        UserInfoEncryptedResponseAlg = EncryptionAlgorithms.KeyManagement.RsaOaep,
        UserInfoEncryptedResponseEnc = EncryptionAlgorithms.ContentEncryption.Aes128Gcm,
        IntrospectionSignedResponseAlg = SigningAlgorithms.PS384,
        IntrospectionEncryptedResponseAlg = EncryptionAlgorithms.KeyManagement.EcdhEs,
        IntrospectionEncryptedResponseEnc = EncryptionAlgorithms.ContentEncryption.Aes192Gcm,
        AuthorizationSignedResponseAlg = SigningAlgorithms.ES512,
        AuthorizationEncryptedResponseAlg = EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW,
        AuthorizationEncryptedResponseEnc = EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256,
        RequestObjectSigningAlg = SigningAlgorithms.PS512,
        RequestObjectEncryptionAlg = EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW,
        RequestObjectEncryptionEnc = EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512,
        TlsClientAuthSubjectDn = "CN=client",
        TlsClientAuthSanDns = ["client.example.com"],
        TlsClientAuthSanUri = [new Uri("https://san.example.com/")],
        TlsClientAuthSanIp = ["192.0.2.1"],
        TlsClientAuthSanEmail = ["cert@client.example.com"],
        DefaultMaxAge = TimeSpan.FromMinutes(5),
        RequireAuthTime = true,
        DefaultAcrValues = ["urn:example:loa:2"],
        InitiateLoginUri = new Uri("https://client.example.com/login"),
        RequestUris = [new Uri("https://client.example.com/request")],
        PkceRequired = false,
        OfflineAccess = OfflineAccess.Disabled,
        DpopBoundAccessTokens = true,
        RequirePushedAuthorizationRequests = true,
        RequireSignedRequestObject = true,
        TlsClientCertificateBoundAccessTokens = true,
        AuthorizationDetailsTypes = ["payment_initiation"],
        TokenExchangeSubjectTokenTypes = [new Uri(TokenExchangeTokenTypes.AccessToken)],
        TokenExchangeAudiences = ["https://api.example.com"],
        BackChannelLogoutUri = new Uri("https://client.example.com/bc-logout"),
        BackChannelLogoutSessionRequired = false,
        FrontChannelLogoutUri = new Uri("https://client.example.com/fc-logout"),
        FrontChannelLogoutSessionRequired = false,
        BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
        BackChannelClientNotificationEndpoint = new Uri("https://client.example.com/ciba"),
        BackChannelAuthenticationRequestSigningAlg = SigningAlgorithms.RS512,
        BackChannelUserCodeParameter = true,
        SoftwareId = "software",
        SoftwareVersion = "1.0",
    };
}
