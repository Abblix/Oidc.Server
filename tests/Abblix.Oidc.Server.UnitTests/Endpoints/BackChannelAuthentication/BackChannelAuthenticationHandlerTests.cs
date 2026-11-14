// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.RequestFetching;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication;

/// <summary>
/// CIBA Core 1.0 section 7.2 has the server authenticate the client before it validates the signed authentication
/// request, so the handler authenticates once, before the request object is read, and hands that client to both
/// the fetcher and the validator.
/// </summary>
public class BackChannelAuthenticationHandlerTests
{
    private readonly Mock<IClientAuthenticator> _clientAuthenticator = new(MockBehavior.Strict);
    private readonly Mock<IBackChannelAuthenticationRequestFetcher> _fetcher = new(MockBehavior.Strict);
    private readonly Mock<IBackChannelAuthenticationRequestValidator> _validator = new(MockBehavior.Strict);
    private readonly Mock<IBackChannelAuthenticationRequestProcessor> _processor = new(MockBehavior.Strict);

    private readonly BackChannelAuthenticationRequest _request = new() { Request = "header.payload.signature" };
    private readonly ClientRequest _clientRequest = new() { ClientId = "client-1" };

    private BackChannelAuthenticationHandler Handler() => new(
        _clientAuthenticator.Object, _fetcher.Object, _validator.Object, _processor.Object);

    /// <summary>
    /// A caller that does not authenticate is answered invalid_client (CIBA Core 1.0 section 13) and nothing it sent is
    /// read: the strict fetcher, validator and processor fail the test if called.
    /// </summary>
    [Fact]
    public async Task AnUnauthenticatedCaller_IsInvalidClient_BeforeTheRequestIsRead()
    {
        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, _clientRequest))
            .ReturnsAsync((ClientInfo?)null);

        var result = await Handler().HandleAsync(SingleIssuer.Tenant, _request, _clientRequest);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClient, error.Error);
    }

    /// <summary>
    /// The client that authenticated is the one the request object is fetched for and the one the request is validated
    /// for, and it authenticates once.
    /// </summary>
    [Fact]
    public async Task TheAuthenticatedClient_IsHandedToTheFetcherAndTheValidator_AuthenticatingOnce()
    {
        var client = new ClientInfo("client-1");
        var fetched = _request with { LoginHint = "end-user" };
        var refusal = new OidcError(ErrorCodes.InvalidScope, "refused");

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, _clientRequest))
            .ReturnsAsync(client);
        _fetcher
            .Setup(f => f.FetchAsync(TestTenant.Matched, client, _request))
            .ReturnsAsync(fetched);
        _validator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, client, fetched, _clientRequest))
            .ReturnsAsync(refusal);

        var result = await Handler().HandleAsync(SingleIssuer.Tenant, _request, _clientRequest);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Same(refusal, error);
        _clientAuthenticator.Verify(
            a => a.TryAuthenticateClientAsync(TestTenant.Matched, _clientRequest), Times.Once);
    }

    /// <summary>
    /// A request object the fetcher refuses for the authenticated client is answered with the fetcher's error and is
    /// not validated.
    /// </summary>
    [Fact]
    public async Task ARefusedRequestObject_IsAnsweredWithTheFetchersError()
    {
        var client = new ClientInfo("client-1");

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, _clientRequest))
            .ReturnsAsync(client);
        _fetcher
            .Setup(f => f.FetchAsync(TestTenant.Matched, client, _request))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidRequestObject, "The request object is invalid."));

        var result = await Handler().HandleAsync(SingleIssuer.Tenant, _request, _clientRequest);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }
}
