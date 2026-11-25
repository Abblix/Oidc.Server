// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Common.Configuration;
using System.Globalization;
using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

// What a client assertion is refused for before its jti is reserved: a client_id naming another client, and a
// lifetime past the deployment's ceiling
public partial class PrivateKeyJwtAuthenticatorTests
{
    /// <summary>
    /// RFC 7523 section 3 item 4: the server "may reject JWTs with an "exp" claim value that is unreasonably far in
    /// the future". An assertion valid for longer than the deployment's ceiling, from now or from its own iat, is
    /// refused before its jti is reserved; one hour by default, as configured otherwise. Measured from now it allows the
    /// forward clock skew, five minutes without a profile, so a client whose clock runs ahead may mint exactly the
    /// ceiling.
    /// </summary>
    [Theory]
    [InlineData(30, null, null, true)]
    [InlineData(66, null, null, false)]
    [InlineData(61, 1, null, true)]
    [InlineData(64, 4, null, true)]
    [InlineData(30, -31, null, false)]
    [InlineData(30, -29, null, true)]
    [InlineData(90, null, 120, true)]
    public async Task AnAssertionValidForLongerThanTheCeiling_IsRefused(
        int expiresInMinutes, int? issuedMinutesAgo, int? ceilingMinutes, bool accepted)
    {
        var (authenticator, mocks) = CreateAuthenticator(
            new Uri(TokenEndpoint),
            clientAssertionMaxLifetime: ceilingMinutes is { } minutes ? TimeSpan.FromMinutes(minutes) : null);
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "jti-of-a-long-assertion", Now.AddMinutes(expiresInMinutes));
        if (issuedMinutesAgo is { } ago)
            token.Payload.IssuedAt = Now.AddMinutes(ago);
        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, It.IsAny<IClientInfoProvider>(), JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<System.Collections.Generic.IReadOnlySet<string>?>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, CreateClientInfo(ClientId)));

        var result = await authenticator.TryAuthenticateClientAsync(
            TenantAt(ClientSecurityProfile.None),
            new ClientRequest { ClientAssertionType = ClientAssertionTypes.JwtBearer, ClientAssertion = JwtAssertion },
            Clients);

        Assert.Equal(accepted, result.TryGetSuccess(out _));
        mocks.ReplayCache.Verify(
            r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<System.Threading.CancellationToken>()),
            accepted ? Times.Once() : Times.Never());
    }

    /// <summary>
    /// RFC 7521 section 4.2: "If present, the value of the "client_id" parameter MUST identify the same client as is
    /// identified by the client assertion", whatever profile the client is held to. A request naming another client is
    /// refused before the assertion's jti is reserved, so the assertion stays usable by its client.
    /// </summary>
    [Theory]
    [InlineData("someone-else", false)]
    [InlineData(ClientId, true)]
    [InlineData(null, true)]
    public async Task AClientIdNamingAnotherClient_IsRefusedBeforeTheJtiIsSpent(string? named, bool accepted)
    {
        var (authenticator, mocks) = CreateAuthenticator();
        var validToken = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "jti-of-a-named-request",
            DateTimeOffset.Parse("2027-01-01T00:05:00Z", CultureInfo.InvariantCulture));
        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, It.IsAny<IClientInfoProvider>(), JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<System.Collections.Generic.IReadOnlySet<string>?>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(validToken, CreateClientInfo(ClientId)));

        var result = await authenticator.TryAuthenticateClientAsync(
            TenantAt(ClientSecurityProfile.None),
            new ClientRequest
            {
                ClientId = named,
                ClientAssertionType = ClientAssertionTypes.JwtBearer,
                ClientAssertion = JwtAssertion,
            },
            Clients);

        Assert.Equal(accepted, result.TryGetSuccess(out _));
        mocks.ReplayCache.Verify(
            r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<System.Threading.CancellationToken>()),
            accepted ? Times.Once() : Times.Never());
    }
}
