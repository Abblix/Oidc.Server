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
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PushedAuthorization;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.PushedAuthorization;

/// <summary>
/// Unit tests for <see cref="PushedAuthorizationRequestProcessorDecorator"/> verifying single-use
/// enforcement of a pushed authorization <c>request_uri</c> per RFC 9126 section 6.
/// </summary>
public class PushedAuthorizationRequestProcessorDecoratorTests
{
    private readonly Mock<IAuthorizationRequestProcessor> _inner;
    private readonly Mock<IAuthorizationRequestStorage> _storage;
    private readonly PushedAuthorizationRequestProcessorDecorator _decorator;

    public PushedAuthorizationRequestProcessorDecoratorTests()
    {
        _inner = new Mock<IAuthorizationRequestProcessor>(MockBehavior.Strict);
        _storage = new Mock<IAuthorizationRequestStorage>(MockBehavior.Strict);
        _decorator = new PushedAuthorizationRequestProcessorDecorator(_inner.Object, _storage.Object);
    }

    private static ValidAuthorizationRequest CreateValidRequest(Uri? requestUri)
    {
        var model = new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
            PushedRequestUri = requestUri,
        };
        var context = new AuthorizationValidationContext(model)
        {
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        };
        return new ValidAuthorizationRequest(context);
    }

    private static SuccessfullyAuthenticated Success(ValidAuthorizationRequest request)
        => new(request.Model, ResponseModes.Query, "session_1", Array.Empty<string>());

    /// <summary>
    /// On a terminal success originating from a pushed request, the request_uri is consumed exactly once.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_SuccessWithPushedRequestUri_ConsumesRequestUri()
    {
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:single-use");
        var request = CreateValidRequest(requestUri);
        _inner.Setup(p => p.ProcessAsync(request)).ReturnsAsync(Success(request));
        _storage.Setup(s => s.TryGetAsync(requestUri, true)).ReturnsAsync((AuthorizationRequest?)null);

        var response = await _decorator.ProcessAsync(request);

        Assert.IsType<SuccessfullyAuthenticated>(response);
        _storage.Verify(s => s.TryGetAsync(requestUri, true), Times.Once);
    }

    /// <summary>
    /// A success on a non-pushed request (no request_uri) leaves storage untouched.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_SuccessWithoutPushedRequestUri_DoesNotConsume()
    {
        var request = CreateValidRequest(requestUri: null);
        _inner.Setup(p => p.ProcessAsync(request)).ReturnsAsync(Success(request));

        await _decorator.ProcessAsync(request);

        _storage.Verify(s => s.TryGetAsync(It.IsAny<Uri>(), It.IsAny<bool>()), Times.Never);
    }

    /// <summary>
    /// An interactive continuation (login / consent / account selection) leaves the request_uri in place so
    /// the user agent can re-enter the authorization endpoint with the same URN.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_InteractiveContinuation_DoesNotConsume()
    {
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:still-valid");
        var request = CreateValidRequest(requestUri);
        _inner.Setup(p => p.ProcessAsync(request)).ReturnsAsync(new LoginRequired(request.Model));

        await _decorator.ProcessAsync(request);

        _storage.Verify(s => s.TryGetAsync(It.IsAny<Uri>(), It.IsAny<bool>()), Times.Never);
    }
}
