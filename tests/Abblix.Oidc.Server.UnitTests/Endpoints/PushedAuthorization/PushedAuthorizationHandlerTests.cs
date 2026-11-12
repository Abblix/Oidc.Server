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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;

using Moq;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.PushedAuthorization;

/// <summary>
/// RFC 9126 section 2.1: request_uri "MUST NOT be provided" in a pushed request. Strict request object processing
/// (RFC 9101 section 6.3, which FAPI 2.0 mandates) rebuilds the request from the request object alone, so the
/// request_uri a client sent beside it must still reach the validator that refuses it.
/// </summary>
public class PushedAuthorizationHandlerTests
{
    private static readonly Uri SentRequestUri = new("https://client.example.com/request.jwt");

    [Fact]
    public async Task ARequestUriDroppedByStrictProcessing_StillReachesTheValidator()
    {
        var received = new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            Request = "eyJ.request.object",
            RequestUri = SentRequestUri,
        };
        var rebuiltFromTheObjectAlone = new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
        };

        var fetcher = new Mock<IAuthorizationRequestFetcher>(MockBehavior.Strict);
        fetcher
            .Setup(f => f.FetchAsync(TestTenant.Matched, received))
            .ReturnsAsync(rebuiltFromTheObjectAlone);

        AuthorizationRequest? validated = null;
        var validator = new Mock<IPushedAuthorizationRequestValidator>(MockBehavior.Strict);
        validator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, It.IsAny<AuthorizationRequest>(), It.IsAny<ClientRequest>()))
            .Callback((TenantDefinition _, AuthorizationRequest request, ClientRequest _) => validated = request)
            .ReturnsAsync(ErrorFactory.InvalidRequest("refused"));

        var handler = new PushedAuthorizationHandler(
            fetcher.Object,
            validator.Object,
            new Mock<IPushedAuthorizationRequestProcessor>(MockBehavior.Strict).Object);

        await handler.HandleAsync(SingleIssuer.Tenant, received, new ClientRequest());

        Assert.NotNull(validated);
        Assert.Equal(SentRequestUri, validated.RequestUri);
        Assert.Equal(ResponseTypes.Code, Assert.Single(validated.ResponseType ?? []));
    }
}
