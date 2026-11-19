// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A tenant declaring a native app RFC 8252 has an authorization server refuse does not start, and the refusal names
/// the client.
/// </summary>
public class NativeClientsCheckTests
{
    private const string ClientId = "desktop-app";

    /// <summary>
    /// A public native app redirecting to each of the three options RFC 8252 section 7 has offered to it starts.
    /// </summary>
    [Fact]
    public void APublicNativeApp_UsingEachRedirectOption_Starts()
        => Assert.Empty(Check(NativeApp()));

    /// <summary>
    /// RFC 8252 section 8.4: "any private-use URI scheme that doesn't contain a period character (".") SHOULD be
    /// rejected", and section 7.3 has loopback redirects use http on the loopback interface. Each holds for the
    /// redirect URIs and for the post-logout ones.
    /// </summary>
    [Theory]
    [InlineData("myapp:/oauth2redirect", false)]
    [InlineData("myapp:/oauth2redirect", true)]
    [InlineData("http://app.example.com/oauth2redirect", false)]
    [InlineData("http://app.example.com/signed-out", true)]
    public void ANativeApp_RedirectingToASchemeWithoutAPeriodOrToRemoteHttp_IsRefused(string uri, bool postLogout)
    {
        var client = NativeApp();
        if (postLogout)
            client.PostLogoutRedirectUris = [new Uri(uri)];
        else
            client.RedirectUris = [.. client.RedirectUris, new Uri(uri)];

        Assert.Contains($"'{ClientId}'", Assert.Single(Check(client)));
    }

    /// <summary>
    /// RFC 8252 section 8.4 has native apps public except with per-instance secrets, and Appendix A item 4 has a server
    /// "Not assume that native app clients can keep a secret": a native app declared once in the tenant settings serves
    /// every installation, so it authenticates with none, whatever method it names.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic)]
    [InlineData(ClientAuthenticationMethods.ClientSecretPost)]
    [InlineData(ClientAuthenticationMethods.ClientSecretJwt)]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt)]
    [InlineData(ClientAuthenticationMethods.TlsClientAuth)]
    [InlineData(ClientAuthenticationMethods.SelfSignedTlsClientAuth)]
    public void ANativeApp_AuthenticatingWithAnyCredential_IsRefused(string method)
    {
        var client = NativeApp();
        client.TokenEndpointAuthMethod = method;

        Assert.Contains($"'{ClientId}'", Assert.Single(Check(client)));
    }

    /// <summary>
    /// A web client the host declares is held to neither rule.
    /// </summary>
    [Fact]
    public void AConfidentialWebClient_RedirectingToAPrivateUseScheme_Starts()
    {
        var client = NativeApp();
        client.ApplicationType = ApplicationTypes.Web;
        client.TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic;
        client.RedirectUris = [new Uri("myapp:/oauth2redirect")];

        Assert.Empty(Check(client));
    }

    private static ClientInfo NativeApp() => new(ClientId)
    {
        ApplicationType = ApplicationTypes.Native,
        TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
        RedirectUris =
        [
            new Uri("com.example.app:/oauth2redirect"),
            new Uri("https://app.example.com/oauth2redirect"),
            new Uri("http://127.0.0.1/oauth2redirect"),
            new Uri("http://[::1]/oauth2redirect"),
        ],
        PostLogoutRedirectUris = [new Uri("com.example.app:/signed-out")],
    };

    private static string[] Check(ClientInfo client)
    {
        var tenant = new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com"), Clients = [client] };
        return new NativeClientsCheck().Check([tenant], new OidcOptions()).Select(refusal => refusal.Message).ToArray();
    }
}
