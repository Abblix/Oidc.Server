// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using System.Text.Json.Nodes;
using Abblix.Utils;
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
            ResolveTokenDecryptionKeys = _ => new [] { EncryptingKey }.AsAsync(),
            ResolveIssuerSigningKeys = _ => new [] { SigningKey }.AsAsync(),
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
