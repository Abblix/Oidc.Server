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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Model;

/// <summary>
/// The metadata the registration, read and update responses return is every value the server stores for the
/// client (RFC 7591 section 3.2.1, RFC 7592 section 3).
/// </summary>
public class RegisteredClientMetadataTests
{
    /// <summary>
    /// Every member the registration request accepts and the server stores comes back under the same name, so a
    /// member added to the request without one in the response fails here rather than going missing on the wire.
    /// </summary>
    [Fact]
    public void EveryStoredRequestMember_HasAResponseMemberOfTheSameName()
    {
        // The two request members that are not client metadata: the identifier the server assigns, and a software
        // statement the server reads and does not keep, which the registration response returns from the request
        string[] notMetadata = [ClientRegistrationRequest.Parameters.ClientId, ClientRegistrationRequest.Parameters.SoftwareStatement];

        var missing = WireNames(typeof(ClientRegistrationRequest))
            .Except(notMetadata)
            .Except(WireNames(typeof(RegisteredClientMetadata)))
            .ToArray();

        Assert.Empty(missing);
    }

    /// <summary>
    /// A client with every value set returns every member, so a member the mapping forgets fails here.
    /// </summary>
    [Fact]
    public void AClientWithEveryValueSet_ReturnsEveryMember()
    {
        var json = JsonSerializer.SerializeToNode(RegisteredClientMetadata.Of(FullClient()))!.AsObject();

        var absent = WireNames(typeof(RegisteredClientMetadata))
            .Where(name => json[name] is null)
            .ToArray();

        Assert.Empty(absent);
    }

    /// <summary>
    /// Each member carries the stored value, written as the registration request writes it.
    /// </summary>
    [Fact]
    public void AClientWithEveryValueSet_ReturnsItsValues()
    {
        var client = FullClient();

        var json = JsonSerializer.SerializeToNode(RegisteredClientMetadata.Of(client))!.AsObject();
        var readBack = json.Deserialize<ClientRegistrationRequest>()!;

        Assert.Equal(client.ClientUri, readBack.ClientUri);
        Assert.Equal(client.PolicyUri, readBack.PolicyUri);
        Assert.Equal(client.TermsOfServiceUri, readBack.TermsOfServiceUri);
        Assert.Equal(client.PostLogoutRedirectUris, readBack.PostLogoutRedirectUris);
        Assert.Equal(client.DefaultMaxAge, readBack.DefaultMaxAge);
        Assert.Equal(client.RequireAuthTime, readBack.RequireAuthTime);
        Assert.Equal(client.DefaultAcrValues, readBack.DefaultAcrValues);
        Assert.Equal(client.IdentityTokenSignedResponseAlgorithm, readBack.IdTokenSignedResponseAlg);
        Assert.Equal(client.RequestObjectEncryptionMethod, readBack.RequestObjectEncryptionEnc);
        Assert.Equal(client.FrontChannelLogout!.Uri, readBack.FrontChannelLogoutUri);
        Assert.Equal(client.BackChannelLogout!.RequiresSessionId, readBack.BackChannelLogoutSessionRequired);
        Assert.Equal(client.BackChannelClientNotificationEndpoint, readBack.BackChannelClientNotificationEndpoint);
        Assert.Equal(client.TlsClientAuth!.SanEmails, readBack.TlsClientAuthSanEmail);
        Assert.Equal(client.SoftwareVersion, readBack.SoftwareVersion);
        Assert.Equal(client.EffectiveResponseTypes, readBack.ResponseTypes);
        Assert.Equal(client.AllowedScopes, readBack.Scope);
    }

    /// <summary>
    /// A UserInfo or introspection response registered as plain JSON is stored with the <c>none</c> algorithm and
    /// returned the way the specifications say it: with the member left out.
    /// </summary>
    [Fact]
    public void APlainJsonResponse_LeavesItsSigningAlgorithmOut()
    {
        var client = FullClient();
        client.UserInfoSignedResponseAlgorithm = SigningAlgorithms.None;
        client.IntrospectionSignedResponseAlgorithm = SigningAlgorithms.None;

        var metadata = RegisteredClientMetadata.Of(client);

        Assert.Null(metadata.UserInfoSignedResponseAlg);
        Assert.Null(metadata.IntrospectionSignedResponseAlg);
    }

    /// <summary>
    /// A client registering no certificate returns none of the certificate members.
    /// </summary>
    [Fact]
    public void AClientWithoutACertificate_ReturnsNoCertificateMembers()
    {
        var client = FullClient();
        client.TlsClientAuth = null;

        var metadata = RegisteredClientMetadata.Of(client);

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

    private static ClientInfo FullClient() => new("client")
    {
        TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
        TokenEndpointAuthSigningAlgorithm = SigningAlgorithms.ES256,
        ApplicationType = ApplicationTypes.Web,
        RedirectUris = [new Uri("https://client.example.com/callback")],
        PostLogoutRedirectUris = [new Uri("https://client.example.com/signed-out")],
        AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
        AllowedResponseTypes = [[ResponseTypes.Code]],
        AllowedScopes = [Scopes.OpenId, Scopes.Profile],
        ClientName = "Client",
        ClientUri = new Uri("https://client.example.com/"),
        LogoUri = new Uri("https://client.example.com/logo.png"),
        PolicyUri = new Uri("https://client.example.com/privacy"),
        TermsOfServiceUri = new Uri("https://client.example.com/terms"),
        Contacts = ["ops@client.example.com"],
        JwksUri = new Uri("https://client.example.com/jwks"),
        Jwks = new JsonWebKeySet([]),
        SubjectType = SubjectTypes.Pairwise,
        SectorIdentifier = "https://client.example.com/sector",
        IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.ES256,
        IdentityTokenEncryptedResponseAlgorithm = "RSA-OAEP-256",
        IdentityTokenEncryptedResponseEncryption = "A256GCM",
        UserInfoSignedResponseAlgorithm = SigningAlgorithms.RS256,
        UserInfoEncryptedResponseAlgorithm = "RSA-OAEP-256",
        UserInfoEncryptedResponseEncryption = "A256GCM",
        IntrospectionSignedResponseAlgorithm = SigningAlgorithms.RS256,
        IntrospectionEncryptedResponseAlgorithm = "RSA-OAEP-256",
        IntrospectionEncryptedResponseEncryption = "A256GCM",
        AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
        AuthorizationEncryptedResponseAlgorithm = "RSA-OAEP-256",
        AuthorizationEncryptedResponseEncryption = "A256GCM",
        RequestObjectSigningAlgorithm = SigningAlgorithms.PS256,
        RequestObjectEncryptionAlgorithm = "RSA-OAEP-256",
        RequestObjectEncryptionMethod = "A256GCM",
        DefaultMaxAge = TimeSpan.FromMinutes(5),
        RequireAuthTime = true,
        DefaultAcrValues = ["urn:example:loa:2"],
        InitiateLoginUri = new Uri("https://client.example.com/login"),
        RequestUris = [new Uri("https://client.example.com/request")],
        FrontChannelLogout = new FrontChannelLogoutOptions(new Uri("https://client.example.com/fc-logout")),
        BackChannelLogout = new BackChannelLogoutOptions(new Uri("https://client.example.com/bc-logout"), false),
        BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
        BackChannelClientNotificationEndpoint = new Uri("https://client.example.com/ciba"),
        BackChannelAuthenticationRequestSigningAlg = SigningAlgorithms.ES256,
        BackChannelUserCodeParameter = true,
        TlsClientAuth = new TlsClientAuthOptions
        {
            SubjectDn = "CN=client",
            SanDns = ["client.example.com"],
            SanUris = [new Uri("https://client.example.com/")],
            SanIps = ["192.0.2.1"],
            SanEmails = ["ops@client.example.com"],
        },
        TlsClientCertificateBoundAccessTokens = true,
        RequireDPoP = true,
        RequirePushedAuthorizationRequests = true,
        RequireSignedRequestObject = true,
        PkceRequired = true,
        OfflineAccessAllowed = true,
        AuthorizationDetailsTypes = ["payment_initiation"],
        TokenExchangeAllowedSubjectTokenTypes = ["urn:ietf:params:oauth:token-type:access_token"],
        TokenExchangeAllowedAudiences = ["https://api.example.com"],
        SoftwareId = "software",
        SoftwareVersion = "1.0",
    };
}
