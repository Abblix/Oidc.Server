// Abblix OIDC Client Library
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

using Abblix.Oidc.Client.Features.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.E2E.Tests;

/// <summary>
/// RFC 6749 section 4.4, the client asking on its own behalf, against the real provider.
/// </summary>
/// <remarks>
/// This is the one grant with no user anywhere in it: the client's own credentials are the authorization,
/// so what the provider is being asked to accept is exactly what a unit test cannot check for itself -
/// whether the form this client posts is the one the token endpoint expects when there is no code, no
/// redirect address and no session behind it.
/// </remarks>
public class ClientCredentialsTests : IClassFixture<ClientAgainstServerFixture>
{
    /// <summary>
    /// The client the provider registers for this grant, and for no other.
    /// </summary>
    private const string ClientId = "e2e-client-credentials";

    private readonly ClientAgainstServerFixture _fixture;

    public ClientCredentialsTests(ClientAgainstServerFixture fixture) => _fixture = fixture;

    /// <summary>
    /// The provider issues a token to the client itself, and answers with what section 4.4.3 describes: an
    /// access token, and no ID Token, because there is no user to make claims about.
    /// </summary>
    [Fact]
    public async Task TheProviderIssuesATokenToTheClientItself()
    {
        await using var client = _fixture.CreateOidcClient(clientId: ClientId);

        var response = await client.GetRequiredService<ITokenRequestService>()
            .RequestClientCredentialsAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.NotEmpty(response.AccessToken);
        Assert.Equal("Bearer", response.TokenType);
        Assert.Null(response.IdToken);
    }

    /// <summary>
    /// A client the provider has not registered for this grant is refused it.
    /// </summary>
    /// <remarks>
    /// Without this case the one above would pass against a provider that hands the grant to anyone who
    /// authenticates, and the test would be saying nothing about the grant at all. The confidential client
    /// the rest of this suite uses authenticates with the same secret and is registered for the code flow,
    /// so the only thing that differs here is the grant it may ask for.
    /// </remarks>
    [Fact]
    public async Task AClientNotRegisteredForTheGrantIsRefused()
    {
        await using var client = _fixture.CreateOidcClient();

        var exception = await Assert.ThrowsAsync<TokenRequestException>(
            () => client.GetRequiredService<ITokenRequestService>()
                .RequestClientCredentialsAsync(cancellationToken: TestContext.Current.CancellationToken));

        // The literal rather than a constant: this class holds the codes a client must react to, and
        // this one it merely reports. RFC 6749 section 5.2 defines it as "the authenticated client is
        // not authorized to use this authorization grant type".
        Assert.Equal("unauthorized_client", exception.Error);
    }
}
