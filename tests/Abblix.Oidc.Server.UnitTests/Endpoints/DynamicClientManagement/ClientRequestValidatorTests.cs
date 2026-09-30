// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
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
    private readonly ClientRequestValidator _validator;

    public ClientRequestValidatorTests()
    {
        _validator = new ClientRequestValidator(
            _clientInfoProvider.Object,
            _tokenValidator.Object,
            SingleIssuer.Settings);
    }

    private static ClientRequest Request() => new()
    {
        ClientId = ClientId,
        AuthorizationHeader = new AuthenticationHeaderValue("Bearer", "registration.access.token"),
    };

    [Fact]
    public async Task ValidateAsync_TokenBoundToTheClientsRecord_ReturnsValidRequest()
    {
        var clientInfo = new ClientInfo(ClientId) { RegistrationAccessTokenId = TokenId };
        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId)).ReturnsAsync(clientInfo);
        _tokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthenticationHeaderValue?>(), ClientId, TokenId))
            .ReturnsAsync((string?)null);

        var result = await _validator.ValidateAsync(Request());

        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Equal(clientInfo, validRequest.ClientInfo);
        Assert.Equal(TokenId, validRequest.RegistrationAccessTokenId);
    }

    [Fact]
    public async Task ValidateAsync_InvalidToken_ReturnsInvalidTokenError()
    {
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(new ClientInfo(ClientId) { RegistrationAccessTokenId = TokenId });
        _tokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthenticationHeaderValue?>(), ClientId, TokenId))
            .ReturnsAsync("The token is expired");

        var result = await _validator.ValidateAsync(Request());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
    }

    /// <summary>
    /// RFC 7592 section 2.3: a token for a client that does not exist is answered 401 and revoked. With the binding
    /// on the client's record, nothing is left for the token to match, which is the revocation; the error is
    /// <c>invalid_token</c> (RFC 6750, Bearer challenge), and the token is not even read.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ClientVanished_ReturnsInvalidToken()
    {
        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId)).ReturnsAsync((ClientInfo?)null);

        var result = await _validator.ValidateAsync(Request());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        _tokenValidator.VerifyNoOtherCalls();
    }

    /// <summary>
    /// A client no registration made - any the settings configure - carries no token id, so no token manages it,
    /// whatever store serves it and whatever token a registrant kept for an earlier registration under its id.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ClientNoRegistrationMade_ReturnsInvalidToken()
    {
        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId)).ReturnsAsync(new ClientInfo(ClientId));

        var result = await _validator.ValidateAsync(Request());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        _tokenValidator.VerifyNoOtherCalls();
    }
}
