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
/// A tenant declaring a client that redirects to a scheme the user agent runs as script does not start, whichever kind
/// of client it is, and the refusal names the client.
/// </summary>
public class ScriptRedirectUrisCheckTests
{
    private const string ClientId = "script-redirect";

    [Theory]
    [InlineData("javascript:alert(1)", ApplicationTypes.Web, false)]
    [InlineData("data:text/html,callback", ApplicationTypes.Web, false)]
    [InlineData("VBScript:msgbox(1)", ApplicationTypes.Web, false)]
    [InlineData("javascript:alert(1)", ApplicationTypes.Native, false)]
    [InlineData("javascript:alert(1)", ApplicationTypes.Web, true)]
    [InlineData("data:text/html,signed-out", ApplicationTypes.Native, true)]
    public void AClient_RedirectingToAScriptScheme_IsRefused(string uri, string applicationType, bool postLogout)
    {
        var client = new ClientInfo(ClientId) { ApplicationType = applicationType };
        if (postLogout)
            client.PostLogoutRedirectUris = [new Uri(uri)];
        else
            client.RedirectUris = [new Uri(uri)];

        Assert.Contains($"'{ClientId}'", Assert.Single(Check(client)));
    }

    /// <summary>
    /// Any other scheme starts, a web client's private-use one included.
    /// </summary>
    [Theory]
    [InlineData("https://app.example.com/cb")]
    [InlineData("myapp:/cb")]
    [InlineData("com.example.app:/cb")]
    public void AClient_RedirectingToAnotherScheme_Starts(string uri)
        => Assert.Empty(Check(new ClientInfo(ClientId)
        {
            RedirectUris = [new Uri(uri)],
            PostLogoutRedirectUris = [new Uri(uri)],
        }));

    /// <summary>
    /// A native app redirecting to a script scheme is refused once, by this check: the native redirect rule leaves
    /// script schemes to it.
    /// </summary>
    [Fact]
    public void ANativeApp_RedirectingToAScriptScheme_IsRefusedOnce()
    {
        var client = new ClientInfo(ClientId)
        {
            ApplicationType = ApplicationTypes.Native,
            TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
            RedirectUris = [new Uri("javascript:alert(1)")],
        };
        var tenant = new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com"), Clients = [client] };

        var refusals = new ScriptRedirectUrisCheck().Check([tenant], new OidcOptions())
            .Concat(new NativeClientsCheck().Check([tenant], new OidcOptions()));

        Assert.Contains($"'{ClientId}'", Assert.Single(refusals).Message);
    }

    private static string[] Check(ClientInfo client)
    {
        var tenant = new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com"), Clients = [client] };
        return new ScriptRedirectUrisCheck().Check([tenant], new OidcOptions()).Select(refusal => refusal.Message).ToArray();
    }
}
