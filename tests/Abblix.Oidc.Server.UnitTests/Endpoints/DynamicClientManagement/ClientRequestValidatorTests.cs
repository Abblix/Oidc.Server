// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// Unit tests for <see cref="ClientRequestValidator"/> - the RFC 7592 client configuration
/// endpoint authentication gate. The endpoint authenticates with a Bearer registration access
/// token, so every failure must speak the Bearer vocabulary of RFC 6750.
/// </summary>
public class ClientRequestValidatorTests
{
    // Reuse the suite-wide client id: LicenseChecker counts distinct client ids in a static set,
    // so a fresh id here would push parallel-running tests over the free-license client limit.
    private const string ClientId = TestConstants.DefaultClientId;
    private const string TokenId = "jti-current";

    private readonly Mock<IClientInfoProvider> _clientInfoProvider = new(MockBehavior.Strict);
    private readonly Mock<IRegistrationAccessTokenValidator> _tokenValidator = new(MockBehavior.Strict);
    private readonly Mock<IRegistrationAccessTokenStore> _tokenStore = new(MockBehavior.Strict);
    private readonly ClientRequestValidator _validator;

    public ClientRequestValidatorTests()
    {
        _validator = new ClientRequestValidator(
            _clientInfoProvider.Object,
            _tokenValidator.Object,
            _tokenStore.Object,
            SingleIssuer.Settings);
    }

    private static ClientRequest Request() => new()
    {
        ClientId = ClientId,
        AuthorizationHeader = new AuthenticationHeaderValue("Bearer", "registration.access.token"),
    };

    [Fact]
    public async Task ValidateAsync_TokenBoundToExistingClient_ReturnsValidRequest()
    {
        var clientInfo = new ClientInfo(ClientId);
        _tokenStore.Setup(s => s.GetTokenIdAsync(ClientId)).ReturnsAsync(TokenId);
        _tokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthenticationHeaderValue?>(), ClientId, TokenId))
            .ReturnsAsync((string?)null);
        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId)).ReturnsAsync(clientInfo);

        var result = await _validator.ValidateAsync(Request());

        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Equal(clientInfo, validRequest.ClientInfo);
    }

    [Fact]
    public async Task ValidateAsync_InvalidToken_ReturnsInvalidTokenError()
    {
        _tokenStore.Setup(s => s.GetTokenIdAsync(ClientId)).ReturnsAsync(TokenId);
        _tokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthenticationHeaderValue?>(), ClientId, TokenId))
            .ReturnsAsync("The token is expired");

        var result = await _validator.ValidateAsync(Request());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        _clientInfoProvider.VerifyNoOtherCalls();
    }

    /// <summary>
    /// RFC 7592 section 2.3: when the addressed client does not exist, the server responds
    /// 401 Unauthorized and the registration access token MUST be immediately revoked.
    /// The error therefore has to be <c>invalid_token</c> (RFC 6750, Bearer challenge) -
    /// <c>invalid_client</c> would produce a Basic challenge that names an authentication
    /// scheme this Bearer-authenticated endpoint never accepts.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ClientVanished_ReturnsInvalidTokenAndRevokesBinding()
    {
        _tokenStore.Setup(s => s.GetTokenIdAsync(ClientId)).ReturnsAsync(TokenId);
        _tokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthenticationHeaderValue?>(), ClientId, TokenId))
            .ReturnsAsync((string?)null);
        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId)).ReturnsAsync((ClientInfo?)null);
        _tokenStore.Setup(s => s.RemoveAsync(ClientId)).Returns(Task.CompletedTask);

        var result = await _validator.ValidateAsync(Request());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        _tokenStore.Verify(s => s.RemoveAsync(ClientId), Times.Once);
    }

    /// <summary>
    /// A client the store serves as one the settings configure is no registration a token could manage, so a
    /// binding that outlived its registration across a restart reaches nothing and is revoked, the same answer as
    /// for a client that does not exist. The id is configured in another case, as client ids compare.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ClientTheStoreServesFromTheSettings_ReturnsInvalidTokenAndRevokesBinding()
    {
        var settings = SingleIssuer.SettingsOf(Options.Create(new OidcOptions
        {
            Clients = [new ClientInfo(ClientId.ToUpperInvariant())],
        }));
        var validator = new ClientRequestValidator(
            new ClientInfoStorage(settings, new SingleIssuerLocal<IssuerClients>()),
            _tokenValidator.Object,
            _tokenStore.Object,
            settings);
        _tokenStore.Setup(s => s.GetTokenIdAsync(ClientId)).ReturnsAsync(TokenId);
        _tokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthenticationHeaderValue?>(), ClientId, TokenId))
            .ReturnsAsync((string?)null);
        _tokenStore.Setup(s => s.RemoveAsync(ClientId)).Returns(Task.CompletedTask);

        var result = await validator.ValidateAsync(Request());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        _tokenStore.Verify(s => s.RemoveAsync(ClientId), Times.Once);
    }

    /// <summary>
    /// Every token this server issues is recorded, so with no record there is no registration a token could manage,
    /// and the token is not even read.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NoBindingRecorded_ReturnsInvalidToken()
    {
        _tokenStore.Setup(s => s.GetTokenIdAsync(ClientId)).ReturnsAsync((string?)null);

        var result = await _validator.ValidateAsync(Request());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        _tokenValidator.VerifyNoOtherCalls();
        _clientInfoProvider.VerifyNoOtherCalls();
    }
}
