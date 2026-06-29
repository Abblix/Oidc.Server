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

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RequestObject;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Unit tests for <see cref="RequestObjectFetchAdapter"/> verifying the OIDC Core §6.1 rule:
/// response_type and client_id passed in the OAuth request syntax must match the values inside
/// the request object when the object carries them.
/// </summary>
public class RequestObjectFetchAdapterTests
{
    private const string ClientId = "client-1";
    private const string RequestJwt = "header.payload.signature";

    private readonly Mock<IRequestObjectFetcher> _requestObjectFetcher = new(MockBehavior.Strict);
    private readonly RequestObjectFetchAdapter _adapter;

    public RequestObjectFetchAdapterTests()
    {
        _adapter = new RequestObjectFetchAdapter(_requestObjectFetcher.Object);
    }

    private static AuthorizationRequest CreateRequest(
        string? clientId = ClientId,
        string[]? responseType = null) => new()
    {
        ClientId = clientId,
        ResponseType = responseType ?? [ResponseTypes.Code],
        RedirectUri = new Uri("https://client.example.com/cb"),
        Request = RequestJwt,
    };

    private void SetupFetcher(AuthorizationRequest merged) =>
        _requestObjectFetcher
            .Setup(f => f.FetchAsync(
                It.IsAny<AuthorizationRequest>(), RequestJwt, It.IsAny<Func<ClientInfo, string?>?>()))
            .ReturnsAsync(merged);

    [Fact]
    public async Task FetchAsync_MatchingParameters_ReturnsMergedRequest()
    {
        var outer = CreateRequest();
        SetupFetcher(CreateRequest());

        var result = await _adapter.FetchAsync(outer);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// OIDC Core §6.1: a request object carrying a different client_id than the OAuth request
    /// syntax must be rejected — otherwise the object could silently swap the client identity.
    /// </summary>
    [Fact]
    public async Task FetchAsync_ClientIdMismatch_ReturnsError()
    {
        var outer = CreateRequest(clientId: ClientId);
        SetupFetcher(CreateRequest(clientId: "another-client"));

        var result = await _adapter.FetchAsync(outer);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// OIDC Core §6.1: the same matching rule applies to response_type — a request object must not
    /// silently switch the flow relative to what the plain OAuth parameters declared.
    /// </summary>
    [Fact]
    public async Task FetchAsync_ResponseTypeMismatch_ReturnsError()
    {
        var outer = CreateRequest(responseType: [ResponseTypes.Code]);
        SetupFetcher(CreateRequest(responseType: [ResponseTypes.Code, ResponseTypes.IdToken]));

        var result = await _adapter.FetchAsync(outer);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }
}
