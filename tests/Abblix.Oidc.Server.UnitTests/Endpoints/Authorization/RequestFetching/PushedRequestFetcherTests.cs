// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Unit tests for <see cref="PushedRequestFetcher"/> verifying the RFC 9126 section 6 per-client
/// require_pushed_authorization_requests metadata: a flagged client may start an authorization
/// flow only via PAR, independent of the server-wide requirement.
/// </summary>
public class PushedRequestFetcherTests
{
    private readonly Mock<IAuthorizationRequestStorage> _storage = new(MockBehavior.Strict);
    private readonly Mock<IClientInfoProvider> _clientInfoProvider = new(MockBehavior.Strict);

    // No flow has ended unless a test says so
    private readonly Mock<IConsumedRequestUriRegistry> _consumedRequestUris = new();

    private PushedRequestFetcher CreateFetcher(bool serverWideRequirement = false)
    {
        var snapshot = new Mock<IOptionsSnapshot<OidcOptions>>();
        snapshot
            .Setup(s => s.Value)
            .Returns(new OidcOptions { RequirePushedAuthorizationRequests = serverWideRequirement });

        return new PushedRequestFetcher(
            snapshot.Object,
            _storage.Object,
            _clientInfoProvider.Object,
            _consumedRequestUris.Object);
    }

    private static AuthorizationRequest CreateRequest() => new()
    {
        ClientId = TestConstants.DefaultClientId,
        ResponseType = [ResponseTypes.Code],
        RedirectUri = TestConstants.DefaultRedirectUri,
        Scope = [Scopes.OpenId],
    };

    /// <summary>
    /// A request stored for a page of a flow that already ended with a code is refused, though the record is still
    /// there.
    /// </summary>
    [Fact]
    public async Task FetchAsync_PageOfEndedFlow_ReturnsInvalidRequestUri()
    {
        var pageUri = new Uri(RequestUrn.Prefix + "page");
        var originUri = new Uri(RequestUrn.Prefix + "pushed");
        _storage
            .Setup(s => s.TryGetAsync(TestTenant.Matched, pageUri, false))
            .ReturnsAsync(CreateRequest() with { OriginRequestUri = originUri });
        _consumedRequestUris.Setup(r => r.IsConsumedAsync(TestTenant.Matched, originUri)).ReturnsAsync(true);

        var result = await CreateFetcher().FetchAsync(SingleIssuer.Tenant, CreateRequest() with { RequestUri = pageUri });

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestUri, error.Error);
    }

    /// <summary>
    /// RFC 9101 section 6.3, which RFC 9126 section 4 applies to a pushed request: the client_id the authorization
    /// request names and the one the pushed request carries must be identical, so a request_uri pushed by one client
    /// is refused when another client names itself.
    /// </summary>
    [Fact]
    public async Task FetchAsync_PushedByAnotherClient_ReturnsInvalidRequestUri()
    {
        var requestUri = new Uri(RequestUrn.Prefix + "pushed");
        _storage
            .Setup(s => s.TryGetAsync(TestTenant.Matched, requestUri, false))
            .ReturnsAsync(CreateRequest());

        var result = await CreateFetcher().FetchAsync(
            SingleIssuer.Tenant,
            new AuthorizationRequest { ClientId = "another-client", RequestUri = requestUri });

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestUri, error.Error);
    }

    /// <summary>
    /// The pushing client naming itself, or a request naming no client at all, gets the pushed request back, so the
    /// refusal above is about a different client and not about the request_uri.
    /// </summary>
    [Theory]
    [InlineData(TestConstants.DefaultClientId)]
    [InlineData(null)]
    public async Task FetchAsync_PushedBySameClientOrNoneNamed_ReturnsPushedRequest(string? clientId)
    {
        var requestUri = new Uri(RequestUrn.Prefix + "pushed");
        _storage
            .Setup(s => s.TryGetAsync(TestTenant.Matched, requestUri, false))
            .ReturnsAsync(CreateRequest());

        var result = await CreateFetcher().FetchAsync(
            SingleIssuer.Tenant,
            new AuthorizationRequest { ClientId = clientId, RequestUri = requestUri });

        Assert.True(result.TryGetSuccess(out var request));
        Assert.Equal(TestConstants.DefaultClientId, request.ClientId);
        Assert.Equal(requestUri, request.PushedRequestUri);
    }

    [Fact]
    public async Task FetchAsync_FlaggedClientWithoutPushedRequest_ReturnsError()
    {
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, TestConstants.DefaultClientId))
            .ReturnsAsync(new ClientInfo(TestConstants.DefaultClientId)
            {
                RequirePushedAuthorizationRequests = true,
            });

        var result = await CreateFetcher().FetchAsync(SingleIssuer.Tenant, CreateRequest());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    [Fact]
    public async Task FetchAsync_UnflaggedClientWithoutPushedRequest_PassesThrough()
    {
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, TestConstants.DefaultClientId))
            .ReturnsAsync(new ClientInfo(TestConstants.DefaultClientId));

        var request = CreateRequest();
        var result = await CreateFetcher().FetchAsync(SingleIssuer.Tenant, request);

        Assert.True(result.TryGetSuccess(out var passed));
        Assert.Same(request, passed);
    }

    /// <summary>
    /// The server-wide requirement keeps precedence and fires before any client lookup.
    /// </summary>
    [Fact]
    public async Task FetchAsync_ServerWideRequirement_ReturnsErrorWithoutClientLookup()
    {
        var result = await CreateFetcher(serverWideRequirement: true).FetchAsync(SingleIssuer.Tenant, CreateRequest());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(It.IsAny<TenantDefinition>(), It.IsAny<string>()), Times.Never);
    }

    /// <summary>
    /// A FAPI 2.0 client must use PAR even though its require_pushed_authorization_requests flag is
    /// unset and the server-wide requirement is off - the profile imposes PAR and the granular toggle
    /// cannot weaken it.
    /// </summary>
    [Fact]
    public async Task FetchAsync_Fapi2ClientWithoutPushedRequest_ReturnsError()
    {
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, TestConstants.DefaultClientId))
            .ReturnsAsync(new ClientInfo(TestConstants.DefaultClientId)
            {
                SecurityProfile = ClientSecurityProfile.Fapi2,
            });

        var result = await CreateFetcher().FetchAsync(SingleIssuer.Tenant, CreateRequest());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// A client that states no profile inherits the server-wide DefaultSecurityProfile=FAPI 2.0, which
    /// imposes PAR on it.
    /// </summary>
    [Fact]
    public async Task FetchAsync_GlobalDefaultFapi2_ImposesPushedRequestOnUnprofiledClient()
    {
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, TestConstants.DefaultClientId))
            .ReturnsAsync(new ClientInfo(TestConstants.DefaultClientId));

        var result = await CreateFetcher()
            .FetchAsync(new TestIssuer { DefaultSecurityProfile = ClientSecurityProfile.Fapi2 }.ToTenant(), CreateRequest());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// A client selecting None under a server-wide FAPI 2.0 default is still held to it, so a request
    /// that was not pushed is refused. The profile requires every authorization flow to start through
    /// a pushed request, of every client the deployment serves.
    /// </summary>
    [Fact]
    public async Task FetchAsync_ExplicitNoneUnderGlobalDefaultFapi2_StillRefuses()
    {
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, TestConstants.DefaultClientId))
            .ReturnsAsync(new ClientInfo(TestConstants.DefaultClientId)
            {
                SecurityProfile = ClientSecurityProfile.None,
            });

        var request = CreateRequest();
        var result = await CreateFetcher().FetchAsync(new TestIssuer { DefaultSecurityProfile = ClientSecurityProfile.Fapi2 }.ToTenant(), request);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }
}
