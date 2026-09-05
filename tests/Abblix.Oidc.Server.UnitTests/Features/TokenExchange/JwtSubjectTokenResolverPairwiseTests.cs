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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.TokenExchange;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.TokenExchange;

/// <summary>
/// Covers the pairwise recovery path of <see cref="JwtSubjectTokenResolver"/>: when a subject_token was issued to a
/// pairwise client, its <c>sub</c> is that client's per-sector pseudonym, and the resolver must look the client up
/// and open the pseudonym back to the real subject. The general resolver tests exercise only the public pass-through
/// path (no settings, no client), so this fills the gap. It runs in the License collection because the client lookup
/// runs a licence check.
/// </summary>
public class JwtSubjectTokenResolverPairwiseTests
{
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
            .Setup(p => p.TryFindClientAsync(OriginalClientId))
            .ReturnsAsync(_pairwiseClient);

        _resolver = new JwtSubjectTokenResolver(_jwtValidator.Object, _converter, _clientInfoProvider.Object);
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
                ClientId = OriginalClientId,
                IssuedAt = now,
                ExpiresAt = now.AddHours(1),
            },
        };
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, SubjectTokenValidation))
            .ReturnsAsync(jwt);

        var result = await _resolver.ResolveAsync(TokenWire, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.Equal(RealSubject, ctx.Subject);
        Assert.Equal(OriginalClientId, ctx.OriginalClientId);
    }
}
