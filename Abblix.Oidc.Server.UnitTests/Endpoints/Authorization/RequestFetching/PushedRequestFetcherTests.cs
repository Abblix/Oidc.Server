// Abblix OIDC Server Library
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

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Unit tests for <see cref="PushedRequestFetcher"/> verifying the RFC 9126 §6 per-client
/// require_pushed_authorization_requests metadata: a flagged client may start an authorization
/// flow only via PAR, independent of the server-wide requirement.
/// </summary>
public class PushedRequestFetcherTests
{
    private readonly Mock<IAuthorizationRequestStorage> _storage = new(MockBehavior.Strict);
    private readonly Mock<IClientInfoProvider> _clientInfoProvider = new(MockBehavior.Strict);

    private PushedRequestFetcher CreateFetcher(bool serverWideRequirement = false)
    {
        var snapshot = new Mock<IOptionsSnapshot<OidcOptions>>();
        snapshot
            .Setup(s => s.Value)
            .Returns(new OidcOptions { RequirePushedAuthorizationRequests = serverWideRequirement });

        return new PushedRequestFetcher(snapshot.Object, _storage.Object, _clientInfoProvider.Object);
    }

    private static AuthorizationRequest CreateRequest() => new()
    {
        ClientId = TestConstants.DefaultClientId,
        ResponseType = [ResponseTypes.Code],
        RedirectUri = TestConstants.DefaultRedirectUri,
        Scope = [Scopes.OpenId],
    };

    [Fact]
    public async Task FetchAsync_FlaggedClientWithoutPushedRequest_ReturnsError()
    {
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestConstants.DefaultClientId))
            .ReturnsAsync(new ClientInfo(TestConstants.DefaultClientId)
            {
                RequirePushedAuthorizationRequests = true,
            });

        var result = await CreateFetcher().FetchAsync(CreateRequest());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    [Fact]
    public async Task FetchAsync_UnflaggedClientWithoutPushedRequest_PassesThrough()
    {
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestConstants.DefaultClientId))
            .ReturnsAsync(new ClientInfo(TestConstants.DefaultClientId));

        var request = CreateRequest();
        var result = await CreateFetcher().FetchAsync(request);

        Assert.True(result.TryGetSuccess(out var passed));
        Assert.Same(request, passed);
    }

    /// <summary>
    /// The server-wide requirement keeps precedence and fires before any client lookup.
    /// </summary>
    [Fact]
    public async Task FetchAsync_ServerWideRequirement_ReturnsErrorWithoutClientLookup()
    {
        var result = await CreateFetcher(serverWideRequirement: true).FetchAsync(CreateRequest());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(It.IsAny<string>()), Times.Never);
    }
}
