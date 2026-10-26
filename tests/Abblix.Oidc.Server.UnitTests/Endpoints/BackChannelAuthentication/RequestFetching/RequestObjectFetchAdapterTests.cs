// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.RequestFetching;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RequestObject;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.RequestFetching;

/// <summary>
/// Pins what the backchannel authentication endpoint hands the request object fetcher: the tenant the request is
/// served at, the request's own request parameter, and the client's signing algorithm for backchannel requests.
/// </summary>
public class RequestObjectFetchAdapterTests
{
    private const string RequestJwt = "header.payload.signature";

    /// <summary>
    /// The request object is validated and merged at the tenant the request is served at, so a client of that tenant
    /// is the one whose keys and signing algorithm judge it.
    /// </summary>
    [Fact]
    public async Task FetchAsync_HandsTheServingTenantAndTheBackChannelSigningAlgorithm()
    {
        var outer = new BackChannelAuthenticationRequest { Scope = [Scopes.OpenId], Request = RequestJwt };
        var merged = outer with { LoginHint = "end-user" };
        var signingClient = new ClientInfo("client-1")
        {
            BackChannelAuthenticationRequestSigningAlg = SigningAlgorithms.PS256,
        };

        var fetcher = new Mock<IRequestObjectFetcher>(MockBehavior.Strict);
        fetcher
            .Setup(f => f.FetchAsync(
                TestTenant.Matched,
                outer,
                RequestJwt,
                It.Is<Func<ClientInfo, string?>>(alg => alg(signingClient) == SigningAlgorithms.PS256)))
            .ReturnsAsync(merged);

        var result = await new RequestObjectFetchAdapter(fetcher.Object).FetchAsync(SingleIssuer.Tenant, outer);

        Assert.True(result.TryGetSuccess(out var value));
        Assert.Same(merged, value);
    }
}
