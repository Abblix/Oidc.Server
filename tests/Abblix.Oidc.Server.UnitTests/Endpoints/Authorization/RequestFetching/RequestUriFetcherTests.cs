// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.RequestFetching;

/// <summary>
/// The request object passed by reference (RFC 9101 section 5.2).
/// </summary>
public class RequestUriFetcherTests
{
    /// <summary>
    /// RFC 9101 section 5: "client_id REQUIRED. OAuth 2.0 [RFC6749] "client_id". The value MUST match the "request" or
    /// "request_uri" Request Object's (Section 2.1) "client_id"." A request_uri without a client_id beside it is refused
    /// with invalid_request before anything is fetched, as a request object passed by value is.
    /// </summary>
    [Fact]
    public async Task ARequestUriWithoutAnOuterClientId_IsAnInvalidRequest()
    {
        var fetcher = new RequestUriFetcher(
            NullLogger<RequestUriFetcher>.Instance,
            new Mock<IClientInfoProvider>(MockBehavior.Strict).Object,
            new Mock<ISecureHttpFetcher>(MockBehavior.Strict).Object);

        var result = await fetcher.FetchAsync(
            SingleIssuer.Tenant,
            new AuthorizationRequest { RequestUri = new Uri("https://client.example.com/request.jwt") });

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// A request object a client serves as a file may end in a line break, which is not part of the token: it is
    /// passed on without it.
    /// </summary>
    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public async Task AFetchedRequestObjectEndingInALineBreak_IsPassedOnWithoutIt(string ending)
    {
        var requestUri = new Uri("https://client.example.com/request.jwt");
        var clients = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        clients
            .Setup(provider => provider.TryFindClientAsync(It.IsAny<TenantDefinition>(), "client"))
            .ReturnsAsync(new ClientInfo("client") { RequestUris = [requestUri] });
        var http = new Mock<ISecureHttpFetcher>(MockBehavior.Strict);
        http
            .Setup(fetcher => fetcher.FetchAsync<string>(requestUri, false))
            .ReturnsAsync("header.payload.signature" + ending);
        var fetcher = new RequestUriFetcher(NullLogger<RequestUriFetcher>.Instance, clients.Object, http.Object);

        var result = await fetcher.FetchAsync(
            SingleIssuer.Tenant,
            new AuthorizationRequest { ClientId = "client", RequestUri = requestUri });

        Assert.True(result.TryGetSuccess(out var request));
        Assert.Equal("header.payload.signature", request.Request);
    }
}
