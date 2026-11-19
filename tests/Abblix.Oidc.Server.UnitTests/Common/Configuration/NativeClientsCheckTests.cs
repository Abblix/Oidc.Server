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
/// A tenant declaring a client RFC 8252 has an authorization server refuse does not start, and the refusal names the
/// client and the rule.
/// </summary>
public class NativeClientsCheckTests
{
    private const string ClientId = "desktop-app";

    /// <summary>
    /// A native app redirecting to each of the three options RFC 8252 section 7 has offered to it, with PKCE and no
    /// secret, starts.
    /// </summary>
    [Fact]
    public void ANativeApp_UsingEachRedirectOption_WithPkceAndNoSecret_Starts()
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

        var refusal = Assert.Single(Check(client));

        Assert.Contains($"'{ClientId}'", refusal);
        Assert.Contains("RFC 8252 section 7.1", refusal);
    }

    /// <summary>
    /// The javascript, data and vbscript schemes run as script in this server's origin when a response is posted to
    /// them, whichever kind of client names them.
    /// </summary>
    [Theory]
    [InlineData("javascript:alert(1)", ApplicationTypes.Web)]
    [InlineData("data:text/html,callback", ApplicationTypes.Web)]
    [InlineData("VBScript:msgbox(1)", ApplicationTypes.Web)]
    [InlineData("javascript:alert(1)", ApplicationTypes.Native)]
    public void AClient_RedirectingToAScriptScheme_IsRefused(string uri, string applicationType)
    {
        var client = NativeApp();
        client.ApplicationType = applicationType;
        client.RedirectUris = [new Uri(uri)];

        var refusal = Assert.Single(Check(client));

        Assert.Contains($"'{ClientId}'", refusal);
        Assert.Contains("runs as script", refusal);
    }

    /// <summary>
    /// A web client the host declares is not held to the native redirect rule.
    /// </summary>
    [Fact]
    public void AWebClient_RedirectingToAPrivateUseScheme_Starts()
    {
        var client = NativeApp();
        client.ApplicationType = ApplicationTypes.Web;
        client.RedirectUris = [new Uri("myapp:/oauth2redirect")];

        Assert.Empty(Check(client));
    }

    /// <summary>
    /// RFC 8252 section 8.1: "Authorization servers SHOULD reject authorization requests from native apps that don't
    /// use PKCE".
    /// </summary>
    [Fact]
    public void ANativeApp_WithPkceTurnedOff_IsRefused()
    {
        var client = NativeApp();
        client.PkceRequired = false;

        var refusal = Assert.Single(Check(client));

        Assert.Contains($"'{ClientId}'", refusal);
        Assert.Contains("RFC 8252 section 8.1", refusal);
    }

    /// <summary>
    /// RFC 8252 section 8.5: a server requiring "a statically included shared secret for native app clients MUST treat
    /// the client as a public client ... and not accept the secret as proof of the client's identity". A client the
    /// host declares is shared by every installation, and the server cannot tell its secret's copies apart. A method
    /// proving a key is not a shared secret.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, true)]
    [InlineData(ClientAuthenticationMethods.ClientSecretPost, true)]
    [InlineData(ClientAuthenticationMethods.ClientSecretJwt, true)]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt, false)]
    public void ANativeApp_AuthenticatingWithASharedSecret_IsRefused(string method, bool refused)
    {
        var client = NativeApp();
        client.TokenEndpointAuthMethod = method;

        var refusals = Check(client);

        Assert.Equal(refused, refusals.Length == 1);
        if (refused)
        {
            Assert.Contains($"'{ClientId}'", refusals[0]);
            Assert.Contains("RFC 8252 section 8.5", refusals[0]);
        }
    }

    /// <summary>
    /// A client declared with no application type is a web client, so a confidential client sharing a secret starts.
    /// </summary>
    [Fact]
    public void AClientDeclaredWithTheDefaults_Starts()
        => Assert.Empty(Check(new ClientInfo(ClientId) { RedirectUris = [new Uri("https://app.example.com/cb")] }));

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
