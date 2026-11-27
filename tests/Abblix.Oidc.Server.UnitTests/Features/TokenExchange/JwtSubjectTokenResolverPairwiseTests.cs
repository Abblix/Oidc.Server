// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.TokenExchange;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Features.TokenExchange;

/// <summary>
/// Covers the pairwise recovery path of <see cref="JwtSubjectTokenResolver"/>: when a subject_token was issued to a
/// pairwise client, its <c>sub</c> is that client's per-sector pseudonym, and the resolver must look the client up
/// and open the pseudonym back to the real subject. The general resolver tests exercise only the public pass-through
/// path (no settings, no client), so this fills the gap. It runs in the License collection because the client lookup
/// runs a license check.
/// </summary>
public class JwtSubjectTokenResolverPairwiseTests
{
    /// <summary>The client requesting the exchange.</summary>
    private static readonly ClientInfo Requester = new("requester");

    private const string TokenWire = "header.payload.signature";
    private const string RealSubject = "real-user-42";
    private const string OriginalClientId = "pairwise-client";

    // RFC 8693 subject tokens are validated with the audience constraint dropped (signature, issuer, lifetime only).
    private const ValidationOptions SubjectTokenValidation =
        ValidationOptions.Default & ~ValidationOptions.RequireValidAudience;

    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator = new(MockBehavior.Strict);
    private readonly Mock<IClientInfoProvider> _clientInfoProvider = new(MockBehavior.Strict);
    private readonly FakeTimeProvider _timeProvider = new();
    private readonly SubjectTypeConverter _converter =
        new(new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) });
    private readonly ClientInfo _pairwiseClient;
    private readonly JwtSubjectTokenResolver _resolver;

    public JwtSubjectTokenResolverPairwiseTests()
    {
        _pairwiseClient = new ClientInfo(OriginalClientId)
        {
            SubjectType = SubjectTypes.Pairwise,
            SectorIdentifier = "sector.example.com",
        };
        _clientInfoProvider
            .Setup(p => p.FindClientAsync(TestTenant.Matched, OriginalClientId))
            .ReturnsAsync(_pairwiseClient);

        _resolver = new JwtSubjectTokenResolver(_jwtValidator.Object, new FixedSubjectTypeConverter(_converter));
    }

    [Fact]
    public async Task PairwiseAccessToken_RecoversRealSubject()
    {
        // The subject_token's 'sub' is the pairwise pseudonym the original client's access token carries; the
        // resolver looks that client up and opens the pseudonym back to the real subject.
        var pairwiseSub = _converter.Convert(RealSubject, _pairwiseClient);
        Assert.NotEqual(RealSubject, pairwiseSub); // the 'sub' really is sealed, not the raw subject

        var now = _timeProvider.GetUtcNow();
        var jwt = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                Subject = pairwiseSub,
                SessionId = "session-1",
                AuthenticationTime = now,
                ClientId = OriginalClientId,
                IssuedAt = now,
                ExpiresAt = now.AddHours(1),
            },
        };
        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, It.IsAny<ClientInfo?>(), It.IsAny<IClientInfoProvider>(), TokenWire, It.IsAny<TokenTypePolicy>(), SubjectTokenValidation))
            .ReturnsAsync(jwt);

        var result = await _resolver.ResolveAsync(SingleIssuer.Tenant, Requester, _clientInfoProvider.Object, TokenWire, new Uri(TokenExchangeTokenTypes.Jwt), CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.Equal(RealSubject, ctx.Subject);
        Assert.Equal(OriginalClientId, ctx.OriginalClientId);
    }

    /// <summary>
    /// A delegated token issued to a pairwise client carries its actors sealed for that client's sector, as its sub
    /// is, so the resolver opens every act.sub of the chain back to the real party: the exchange then seals them for
    /// the requesting client once, instead of sealing a pseudonym a second time.
    /// </summary>
    [Fact]
    public async Task PairwiseDelegatedToken_OpensEveryActorBackToTheRealParty()
    {
        var act = new JsonObject
        {
            [IanaClaimTypes.Sub] = _converter.Convert("current-actor", _pairwiseClient),
            [IanaClaimTypes.Act] = new JsonObject { [IanaClaimTypes.Sub] = _converter.Convert("prior-actor", _pairwiseClient) },
        };

        var result = await ResolveDelegatedAsync(act);

        Assert.True(result.TryGetSuccess(out var ctx));
        var opened = Assert.IsType<JsonObject>(ctx.Act);
        Assert.Equal("current-actor", opened[IanaClaimTypes.Sub]!.GetValue<string>());
        Assert.Equal("prior-actor", opened[IanaClaimTypes.Act]![IanaClaimTypes.Sub]!.GetValue<string>());
    }

    /// <summary>
    /// An actor that does not open for the client the token was issued to (a foreign-sector value) leaves the
    /// delegation chain unknown, so the subject_token is refused rather than exchanged with a wrong actor.
    /// </summary>
    [Fact]
    public async Task PairwiseDelegatedToken_WithAnActorThatDoesNotOpen_IsRefused()
    {
        var foreign = new ClientInfo("other") { SubjectType = SubjectTypes.Pairwise, SectorIdentifier = "other.example.com" };
        var act = new JsonObject
        {
            [IanaClaimTypes.Sub] = _converter.Convert("current-actor", _pairwiseClient),
            [IanaClaimTypes.Act] = new JsonObject { [IanaClaimTypes.Sub] = _converter.Convert("prior-actor", foreign) },
        };

        var result = await ResolveDelegatedAsync(act);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    private async Task<Abblix.Utils.Result<SubjectTokenContext, Abblix.Oidc.Server.Common.OidcError>> ResolveDelegatedAsync(
        JsonObject act)
    {
        var now = _timeProvider.GetUtcNow();
        var jwt = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                Subject = _converter.Convert(RealSubject, _pairwiseClient),
                SessionId = "session-1",
                AuthenticationTime = now,
                ClientId = OriginalClientId,
                IssuedAt = now,
                ExpiresAt = now.AddHours(1),
            },
        };
        jwt.Payload.Json[IanaClaimTypes.Act] = act;
        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, It.IsAny<ClientInfo?>(), It.IsAny<IClientInfoProvider>(), TokenWire, It.IsAny<TokenTypePolicy>(), SubjectTokenValidation))
            .ReturnsAsync(jwt);

        return await _resolver.ResolveAsync(SingleIssuer.Tenant, Requester, _clientInfoProvider.Object, TokenWire, new Uri(TokenExchangeTokenTypes.Jwt), CancellationToken.None);
    }
}
