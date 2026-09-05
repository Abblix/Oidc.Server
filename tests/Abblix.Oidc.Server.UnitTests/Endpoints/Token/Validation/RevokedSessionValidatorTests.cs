// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token.Validation;

/// <summary>
/// The third place a revocation is read: at redemption, against the session the grant was authorized from.
/// </summary>
/// <remarks>
/// Neither of the other two sees this case. The token side compares issue times, and a token minted at
/// redemption is new. The authorization endpoint judged the session when the grant was created and does not
/// see it again. So a grant outstanding when a revocation lands would otherwise redeem, and the refresh
/// family it founds stays past the cutoff for its whole life because rotation carries the first issue time
/// forward.
/// </remarks>
public class RevokedSessionValidatorTests
{
    private static readonly DateTimeOffset AuthenticatedAt = new(2024, 1, 15, 11, 0, 0, TimeSpan.Zero);

    private readonly Mock<IRevocationCutoffChecker> _cutoffs = new(MockBehavior.Strict);
    private readonly RevokedSessionValidator _validator;

    public RevokedSessionValidatorTests()
    {
        _validator = new RevokedSessionValidator(_cutoffs.Object);
    }

    private static TokenValidationContext Context(string grantType) => new(
        new TokenRequest { GrantType = grantType },
        new ClientRequest { ClientId = TestConstants.DefaultClientId })
    {
        AuthorizedGrant = new AuthorizedGrant(
            new AuthSession("user_42", "session_7", AuthenticatedAt, "local"),
            new AuthorizationContext(TestConstants.DefaultClientId, [], null)),
    };

    /// <summary>
    /// A grant whose session a revocation has caught is refused, and refused as <c>invalid_grant</c> - the
    /// code RFC 6749 Section 5.2 defines for a grant that is "invalid, expired, revoked, does not match the
    /// redirection URI used in the authorization request, or was issued to another client".
    /// </summary>
    [Theory]
    [InlineData(GrantTypes.AuthorizationCode)]
    [InlineData(GrantTypes.RefreshToken)]
    [InlineData(GrantTypes.DeviceAuthorization)]
    [InlineData(GrantTypes.Ciba)]
    public async Task AGrantRedeemingARevokedSession_IsRefused(string grantType)
    {
        _cutoffs.Setup(c => c.IsSessionRefusedAsync(It.IsAny<AuthSession>())).ReturnsAsync(true);

        var error = await _validator.ValidateAsync(Context(grantType), CancellationToken.None);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
    }

    /// <summary>
    /// And the same grant passes when no cutoff reaches it. The control: without it every assertion above
    /// holds equally over a validator that refuses everything.
    /// </summary>
    [Theory]
    [InlineData(GrantTypes.AuthorizationCode)]
    [InlineData(GrantTypes.RefreshToken)]
    [InlineData(GrantTypes.DeviceAuthorization)]
    [InlineData(GrantTypes.Ciba)]
    public async Task AGrantWhoseSessionSurvives_IsAccepted(string grantType)
    {
        _cutoffs.Setup(c => c.IsSessionRefusedAsync(It.IsAny<AuthSession>())).ReturnsAsync(false);

        var error = await _validator.ValidateAsync(Context(grantType), CancellationToken.None);

        Assert.Null(error);
    }

    /// <summary>
    /// A grant that builds its session during this very request is not asked about at all.
    /// </summary>
    /// <remarks>
    /// Two reasons, and the store read is the lesser one. These grants stamp the authentication time from
    /// the current clock, so no cutoff can predate it and the question cannot answer yes. And their subject
    /// belongs to somebody else's namespace - under client credentials it is the client identifier, under
    /// the assertion grants a federated issuer's - so matching it against our cutoffs would refuse a
    /// stranger for a revocation that has nothing to do with them.
    /// <para>
    /// Asserted as <c>Times.Never</c> on a strict mock with no setup: either alone would pass on a
    /// validator that simply never ran, so the surviving grant types above are what make this meaningful.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(GrantTypes.ClientCredentials)]
    [InlineData(GrantTypes.JwtBearer)]
    [InlineData(GrantTypes.TokenExchange)]
    [InlineData(GrantTypes.Password)]
    public async Task AGrantBuildingItsOwnSession_IsNotAskedAbout(string grantType)
    {
        var error = await _validator.ValidateAsync(Context(grantType), CancellationToken.None);

        Assert.Null(error);
        _cutoffs.Verify(c => c.IsSessionRefusedAsync(It.IsAny<AuthSession>()), Times.Never);
    }

    /// <summary>
    /// A request naming no grant type is not asked about either, rather than throwing on the way past.
    /// </summary>
    [Fact]
    public async Task ARequestWithNoGrantType_IsNotAskedAbout()
    {
        var context = new TokenValidationContext(
            new TokenRequest(), new ClientRequest { ClientId = TestConstants.DefaultClientId });

        var error = await _validator.ValidateAsync(context, CancellationToken.None);

        Assert.Null(error);
        _cutoffs.Verify(c => c.IsSessionRefusedAsync(It.IsAny<AuthSession>()), Times.Never);
    }
}
