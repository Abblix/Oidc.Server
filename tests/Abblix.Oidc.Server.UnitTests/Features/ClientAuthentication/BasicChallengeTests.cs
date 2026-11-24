// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 3.2.4: the Basic challenge is owed to a client that "attempted to
/// authenticate via the Authorization request header field", HTTP Basic being the server's one scheme for clients, and
/// to a client registered for client_secret_basic; "Client authentication methods that do not use an HTTP
/// authentication scheme have no corresponding challenge".
/// </summary>
public class BasicChallengeTests
{
    private const string ClientId = TestConstants.DefaultClientId;

    private static readonly string BasicCredentials =
        Convert.ToBase64String(Encoding.UTF8.GetBytes($"{ClientId}:wrong"));

    [Theory]
    [InlineData(TokenTypes.Basic, null, true)]
    [InlineData("basic", null, true)]
    [InlineData(null, ClientAuthenticationMethods.ClientSecretBasic, true)]
    [InlineData(null, ClientAuthenticationMethods.ClientSecretPost, false)]
    [InlineData(null, ClientAuthenticationMethods.PrivateKeyJwt, false)]
    [InlineData(null, ClientAuthenticationMethods.None, false)]
    [InlineData(TokenTypes.Bearer, ClientAuthenticationMethods.ClientSecretPost, false)]
    public void IsOwed_ForTheSchemeUsedOrTheMethodRegistered(string? scheme, string? registeredMethod, bool expected)
    {
        var request = new ClientRequest
        {
            AuthorizationHeaderLines = scheme is null ? null : [$"{scheme} {BasicCredentials}"],
        };
        var client = registeredMethod is null
            ? null
            : new ClientInfo(ClientId) { TokenEndpointAuthMethod = registeredMethod };

        Assert.Equal(expected, BasicChallenge.IsOwed(request, client));
    }

    /// <summary>
    /// A request whose client failed to authenticate names it by its client_id, and the client is looked up through the
    /// lookup its authentication made; an unknown client, or a request naming none, is owed no challenge.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, true, true)]
    [InlineData(ClientAuthenticationMethods.ClientSecretPost, true, false)]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, false, false)]
    public async Task InvalidClientAsync_LooksTheNamedClientUp(string registeredMethod, bool known, bool expected)
    {
        var clients = new Mock<IClientInfoProvider>();
        clients
            .Setup(c => c.FindClientAsync(It.IsAny<TenantDefinition>(), ClientId))
            .ReturnsAsync(known
                ? new ClientInfo(ClientId) { TokenEndpointAuthMethod = registeredMethod }
                : (Result<ClientInfo, ClientAbsence>)ClientAbsence.Unknown);

        var refusal = await BasicChallenge.InvalidClientAsync(
            SingleIssuer.Tenant, new ClientRequest { ClientId = ClientId }, clients.Object, "refused");

        Assert.Equal(ErrorCodes.InvalidClient, refusal.Error);
        Assert.Equal(expected, refusal.BasicChallengeOwed);
    }

    [Fact]
    public async Task InvalidClientAsync_WithoutAClientId_OwesNoChallengeAndLooksNothingUp()
    {
        var clients = new Mock<IClientInfoProvider>(MockBehavior.Strict);

        var refusal = await BasicChallenge.InvalidClientAsync(
            SingleIssuer.Tenant, new ClientRequest(), clients.Object, "refused");

        Assert.False(refusal.BasicChallengeOwed);
    }
}
