// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// Unit tests for <see cref="ClientInfo.ClientType"/>, the classification RFC 6749 section 2.1 draws
/// between a client able to keep a credential and one that is not. It is derived from
/// <see cref="ClientInfo.TokenEndpointAuthMethod"/> alone, so each case here sets that one property.
/// </summary>
public class ClientTypeTests
{
    /// <summary>
    /// The single method that makes a client public: it presents no credential at all.
    /// </summary>
    [Fact]
    public void None_YieldsPublic()
    {
        var client = new ClientInfo(TestConstants.DefaultClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
        };

        Assert.Equal(ClientType.Public, client.ClientType);
    }

    /// <summary>
    /// Every method other than <c>none</c> yields a confidential client, and that includes methods the
    /// library does not recognise. Hosts register their own
    /// <see cref="ClientAuthentication.IClientAuthenticator"/> implementations, so narrowing this to an
    /// enumeration of the built-in methods would silently reclassify every host-added method as public
    /// and hand its clients the relaxations reserved for credential-less ones.
    /// </summary>
    [Theory]
    // The built-in methods, each carrying a secret, a signed assertion or a certificate.
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic)]
    [InlineData(ClientAuthenticationMethods.ClientSecretPost)]
    [InlineData(ClientAuthenticationMethods.ClientSecretJwt)]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt)]
    [InlineData(ClientAuthenticationMethods.TlsClientAuth)]
    [InlineData(ClientAuthenticationMethods.SelfSignedTlsClientAuth)]
    // A method a host adds through its own authenticator.
    [InlineData("urn:example:hardware-token")]
    // The comparison is ordinal, so a case variant of "none" is a different method, not the same one.
    [InlineData("NONE")]
    // A value that states no method at all is unrecognised, and unrecognised is confidential.
    [InlineData("")]
    public void AnythingOtherThanNone_YieldsConfidential(string authenticationMethod)
    {
        var client = new ClientInfo(TestConstants.DefaultClientId)
        {
            TokenEndpointAuthMethod = authenticationMethod,
        };

        Assert.Equal(ClientType.Confidential, client.ClientType);
    }

    /// <summary>
    /// A client that states no method at all inherits <c>client_secret_basic</c>, so it is confidential.
    /// A client becomes public only by saying so.
    /// </summary>
    [Fact]
    public void ClientStatingNoMethod_IsConfidential()
    {
        var client = new ClientInfo(TestConstants.DefaultClientId);

        Assert.Equal(ClientType.Confidential, client.ClientType);
    }
}
