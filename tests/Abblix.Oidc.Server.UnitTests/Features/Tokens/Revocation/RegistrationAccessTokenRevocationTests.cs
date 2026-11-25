// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Revocation;

/// <summary>
/// A registration access token is revoked by binding its registration to an identifier no token carries, and only
/// while the registration is still bound to the token revoked.
/// </summary>
public class RegistrationAccessTokenRevocationTests
{
    private const string ClientId = "client_1";
    private const string TokenId = "token_1";
    private const string NewTokenId = "token_2";

    private readonly Mock<IClientInfoManager> _registrations = new(MockBehavior.Strict);
    private readonly RegistrationAccessTokenRevocation _revocation;

    public RegistrationAccessTokenRevocationTests()
    {
        var tokenIds = new Mock<ITokenIdGenerator>();
        tokenIds.Setup(generator => generator.GenerateTokenId()).Returns(NewTokenId);
        _revocation = new RegistrationAccessTokenRevocation(
            _registrations.Object, tokenIds.Object, new RegistrationAccessTokenBinding(_registrations.Object));
    }

    [Fact]
    public async Task The_registration_bound_to_the_token_is_bound_to_a_new_identifier()
    {
        var registration = new RegisteredClient(new ClientInfo(ClientId), TokenId);
        Holds(registration);
        var rebound = registration with { RegistrationAccessTokenId = NewTokenId };
        _registrations
            .Setup(manager => manager.TryUpdateClientAsync(
                TestTenant.Matched,
                registration,
                rebound))
            .ReturnsAsync(true);

        await _revocation.RevokeAsync(SingleIssuer.Tenant, Token(ClientId, TokenId));

        _registrations.VerifyAll();
    }

    [Fact]
    public async Task A_replaced_token_leaves_the_registration_as_it_is()
    {
        Holds(new RegisteredClient(new ClientInfo(ClientId), NewTokenId));

        await _revocation.RevokeAsync(SingleIssuer.Tenant, Token(ClientId, TokenId));

        _registrations.VerifyAll();
    }

    [Fact]
    public async Task A_token_of_a_client_no_longer_registered_changes_nothing()
    {
        _registrations
            .Setup(manager => manager.TryFindRegisteredClientAsync(TestTenant.Matched, ClientId))
            .ReturnsAsync((RegisteredClient?)null);

        await _revocation.RevokeAsync(SingleIssuer.Tenant, Token(ClientId, TokenId));

        _registrations.VerifyAll();
    }

    [Theory]
    [InlineData(null, TokenId)]
    [InlineData(ClientId, null)]
    public async Task A_token_naming_no_client_or_no_identifier_changes_nothing(string? subject, string? tokenId)
    {
        await _revocation.RevokeAsync(SingleIssuer.Tenant, Token(subject, tokenId));

        _registrations.VerifyNoOtherCalls();
    }

    private void Holds(RegisteredClient registration)
        => _registrations
            .Setup(manager => manager.TryFindRegisteredClientAsync(TestTenant.Matched, ClientId))
            .ReturnsAsync(registration);

    private static JsonWebToken Token(string? subject, string? tokenId)
    {
        var token = new JsonWebToken { Header = { Type = JwtTypes.RegistrationAccessToken } };
        token.Payload.Subject = subject;
        token.Payload.JwtId = tokenId;
        return token;
    }
}
