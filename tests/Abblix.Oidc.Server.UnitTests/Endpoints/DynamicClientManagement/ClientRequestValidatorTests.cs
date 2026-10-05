// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
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

    private readonly Mock<IClientInfoManager> _clients = new(MockBehavior.Strict);
    private readonly Mock<IRegistrationAccessTokenValidator> _tokenValidator = new(MockBehavior.Strict);
    private readonly ClientRequestValidator _validator;

    public ClientRequestValidatorTests()
    {
        _validator = new ClientRequestValidator(_clients.Object, _tokenValidator.Object);
    }

    private static ClientRequest Request() => new()
    {
        ClientId = ClientId,
        AuthorizationHeader = new AuthenticationHeaderValue("Bearer", "registration.access.token"),
    };

    private void TokenCarries(string tokenId)
        => _tokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthenticationHeaderValue?>(), ClientId))
            .ReturnsAsync(tokenId);

    private void Holds(RegisteredClient? client)
        => _clients.Setup(c => c.TryFindRegisteredClientAsync(ClientId)).ReturnsAsync(client);

    [Fact]
    public async Task ValidateAsync_TokenTheRegistrationHolds_ReturnsValidRequest()
    {
        var client = new RegisteredClient(new ClientInfo(ClientId), TokenId);
        TokenCarries(TokenId);
        Holds(client);

        var result = await _validator.ValidateAsync(Request());

        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(client, validRequest.Client);
    }

    /// <summary>
    /// A token failing its own checks is refused before any registration is looked up, so the answer is the same
    /// whatever the id names - registered, configured or unknown.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_InvalidToken_IsRefusedBeforeAnyLookup()
    {
        _tokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthenticationHeaderValue?>(), ClientId))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidToken, "The token is expired"));

        var result = await _validator.ValidateAsync(Request());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        _clients.VerifyNoOtherCalls();
    }

    /// <summary>
    /// A token issued before the last rotation carries a jti the registration no longer holds.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenOfAnEarlierRotation_ReturnsInvalidToken()
    {
        TokenCarries("jti-old");
        Holds(new RegisteredClient(new ClientInfo(ClientId), TokenId));

        var result = await _validator.ValidateAsync(Request());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
    }

    /// <summary>
    /// RFC 7592 section 2.3: a token for a client that does not exist is answered 401 and revoked. With nothing left
    /// for the token to match, the revocation is done; a client the settings configure, which no registration made,
    /// is answered alike. The error is <c>invalid_token</c> (RFC 6750, Bearer challenge).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NoRegistrationUnderTheId_ReturnsInvalidToken()
    {
        TokenCarries(TokenId);
        Holds(null);

        var result = await _validator.ValidateAsync(Request());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
    }
}
