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

using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Abblix.Jwt.UnitTests;

public class JwtEncryptionTests
{
    private static readonly JsonWebKey EncryptingKey = JsonWebKeyFactory.CreateRsa(JsonWebKeyUseNames.Enc);
    private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(JsonWebKeyUseNames.Sig);

    [Fact]
    public async Task JwtFullCycleTest()
    {
        var issuedAt = DateTimeOffset.UtcNow;

        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = {
                JwtId = Guid.NewGuid().ToString("N"),
                IssuedAt = issuedAt,
                NotBefore = issuedAt,
                ExpiresAt = issuedAt + TimeSpan.FromDays(1),
                Issuer = "abblix.com",
                Audiences = new []{ nameof(JwtFullCycleTest) },
                ["test"] = "value",
                ["address"] = new JsonObject
                {
                    { "street", "123 Main St" },
                    { "city", "Springfield" },
                    { "state", "IL" },
                    { "zip", "62701" },
                }
            },
        };

        var creator = new JsonWebTokenCreator();
        var jwt = await creator.IssueAsync(token, SigningKey, EncryptingKey);

        var validator = new JsonWebTokenValidator();
        var parameters = new ValidationParameters
        {
            ValidateAudience = aud => Task.FromResult(token.Payload.Audiences.SequenceEqual(aud)),
            ValidateIssuer = iss => Task.FromResult(iss == token.Payload.Issuer),
            ResolveTokenDecryptionKeys = _ => new [] { EncryptingKey }.ToAsyncEnumerable(),
            ResolveIssuerSigningKeys = _ => new [] { SigningKey }.ToAsyncEnumerable(),
        };

        var result = Assert.IsType<ValidJsonWebToken>(await validator.ValidateAsync(jwt, parameters));
        var expectedClaims = ExtractClaims(token);
        var actualClaims = ExtractClaims(result.Token);
        Assert.Equal(expectedClaims, actualClaims);
    }

    private static IEnumerable<(string Key, string?)> ExtractClaims(JsonWebToken token)
        => from claim in token.Payload.Json
            select (claim.Key, claim.Value?.ToJsonString());
}
