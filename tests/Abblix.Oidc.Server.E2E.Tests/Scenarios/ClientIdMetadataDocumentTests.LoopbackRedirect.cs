// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Model;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class ClientIdMetadataDocumentTests
{
    /// <summary>
    /// Section 4.2 makes an exception to the exact match "for redirect URIs on the loopback network interface, which
    /// allow for randomly assigned ports", and RFC 9700 section 4.1.3 has the server "allow variable port numbers" for
    /// a native app "using a localhost URI". A document naming no application type and listing only loopback redirect
    /// URIs without a port, as a command-line app publishes it, is served on the port the app listens on at sign-in,
    /// under <c>localhost</c> as under <c>127.0.0.1</c>, and the code is redeemed there.
    /// </summary>
    [Theory]
    [InlineData("http://localhost:53111/callback")]
    [InlineData("http://127.0.0.1:53111/callback")]
    public async Task ALoopbackRedirectUriOnAnotherPort_IsServedAndItsCodeRedeemed(string redirectUri)
    {
        var document = PublicClientDocument();
        document[RegistrationMembers.RedirectUris] =
            new JsonArray("http://localhost/callback", "http://127.0.0.1/callback");
        Serve(document);
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var (verifier, challenge) = GeneratePkcePair();
        var parameters = CodeFlowParameters(ClientId, challenge);
        parameters[AuthorizationRequest.Parameters.RedirectUri] = redirectUri;

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, parameters);
        var exchange = CodeExchange(code, verifier);
        exchange[TokenRequest.Parameters.RedirectUri] = redirectUri;
        var tokens = await ExchangeCodeForTokensAsync(client, discovery, exchange);

        Assert.NotNull(tokens[TokenResponse.Parameters.AccessToken]);
    }
}
