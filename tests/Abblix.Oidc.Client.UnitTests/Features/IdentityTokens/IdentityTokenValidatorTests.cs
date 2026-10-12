// Abblix OIDC Client Library
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

using Abblix.Jwt;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.IdentityTokens;
using Abblix.Oidc.Client.Features.SigningKeys;
using Abblix.Oidc.Client.Features.TokenValidation;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.UnitTests.Features.IdentityTokens;

/// <summary>
/// The thirteen steps of OpenID Connect Core 1.0 section 3.1.3.7, one case each, against tokens this
/// suite signs itself so every check can be attacked in isolation.
/// </summary>
/// <remarks>
/// Each rejection case changes exactly one thing about a token that otherwise validates, so a passing
/// test says the named check did the rejecting rather than something incidental. The positive case at
/// the top is what makes that claim possible: without it, every rejection could be a token that was
/// broken all along.
/// </remarks>
public class IdentityTokenValidatorTests
{
    private const string Issuer = "https://auth.example.com";
    private const string ClientId = "test-client";

    /// <summary>
    /// Stands in for discovery, so the tests turn on one issuer value rather than on an HTTP fetch.
    /// </summary>
    private sealed class StubMetadataProvider(string issuer) : IProviderMetadataProvider
    {
        public Task<ProviderMetadata> GetMetadataAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new ProviderMetadata { Issuer = issuer });
    }

    /// <summary>
    /// Publishes exactly the key the suite signs with, so a token signed by any other key is a forgery
    /// by construction rather than by configuration.
    /// </summary>
    private sealed class StubSigningKeysProvider(JsonWebKey key) : IIssuerSigningKeysProvider
    {
        public Task<IReadOnlyCollection<JsonWebKey>> GetSigningKeysAsync(
            string? keyId, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyCollection<JsonWebKey>>([key]);
    }

    private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
    private static readonly JsonWebKey OtherKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    private static readonly IServiceProvider Jwt = new ServiceCollection()
        .AddSingleton(TimeProvider.System)
        .AddLogging()
        .AddJsonWebTokens()
        .BuildServiceProvider();

    /// <summary>
    /// A token that satisfies every rule, as the starting point each rejection case then breaks.
    /// </summary>
    private static JsonWebToken ValidToken() => new()
    {
        Header = { Algorithm = SigningAlgorithms.RS256 },
        Payload =
        {
            Issuer = Issuer,
            Audiences = [ClientId],
            Subject = "248289761001",
            IssuedAt = TimeProvider.System.GetUtcNow(),
            ExpiresAt = TimeProvider.System.GetUtcNow().AddHours(1),
        },
    };

    private static Task<string> Issue(JsonWebToken token, JsonWebKey? key = null)
        => Jwt.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, key ?? SigningKey);

    private static IIdentityTokenValidator CreateValidator(
        Action<IdentityTokenValidationOptions>? configure = null,
        string issuer = Issuer,
        Action<ProviderTokenValidationOptions>? configureProvider = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddSingleton<IProviderMetadataProvider>(new StubMetadataProvider(issuer));
        services.AddSingleton<IIssuerSigningKeysProvider>(new StubSigningKeysProvider(SigningKey));
        services.Configure<OidcClientOptions>(o => o.ClientId = ClientId);
        services.AddIdentityTokenValidation(configure);

        if (configureProvider is not null)
            services.Configure(configureProvider);

        return services.BuildServiceProvider().GetRequiredService<IIdentityTokenValidator>();
    }

    private static async Task<IdentityTokenValidationException> AssertRejects(
        JsonWebToken token,
        IdentityTokenValidationContext? context = null,
        JsonWebKey? signingKey = null,
        Action<IdentityTokenValidationOptions>? configure = null,
        Action<ProviderTokenValidationOptions>? configureProvider = null)
    {
        var jwt = await Issue(token, signingKey);

        return await Assert.ThrowsAsync<IdentityTokenValidationException>(
            () => CreateValidator(configure, configureProvider: configureProvider).ValidateAsync(
                jwt, context ?? new IdentityTokenValidationContext(), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ValidToken_IsAccepted()
    {
        var jwt = await Issue(ValidToken());

        var token = await CreateValidator().ValidateAsync(
            jwt, new IdentityTokenValidationContext(), TestContext.Current.CancellationToken);

        Assert.Equal("248289761001", token.Payload.Subject);
    }

    /// <summary>
    /// Step 2: the issuer identifier MUST match exactly. A trailing slash is a different issuer.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com/")]
    [InlineData("https://AUTH.example.com")]
    [InlineData("https://attacker.example.com")]
    public async Task IssuerThatDoesNotMatchExactly_IsRejected(string tokenIssuer)
    {
        var token = ValidToken();
        token.Payload.Issuer = tokenIssuer;

        await AssertRejects(token);
    }

    /// <summary>
    /// Step 3: the token MUST list this client as an audience.
    /// </summary>
    [Fact]
    public async Task AudienceThatIsNotThisClient_IsRejected()
    {
        var token = ValidToken();
        token.Payload.Audiences = ["some-other-client"];

        await AssertRejects(token);
    }

    /// <summary>
    /// Step 3 again, the half that is easy to overlook: a token MUST be rejected when it carries
    /// audiences the client does not trust. This client trusts only itself, so a second audience is a
    /// token the other party can replay here.
    /// </summary>
    [Fact]
    public async Task AdditionalUntrustedAudience_IsRejected()
    {
        var token = ValidToken();
        token.Payload.Audiences = [ClientId, "another-client"];

        await AssertRejects(token);
    }

    /// <summary>
    /// Section 2 lists sub among the REQUIRED claims. An empty one identifies nobody.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task MissingSubject_IsRejected(string? subject)
    {
        var token = ValidToken();
        token.Payload.Subject = subject;

        await AssertRejects(token);
    }

    /// <summary>
    /// Section 2 makes exp REQUIRED. Without it there is no instant at which the token is expired.
    /// </summary>
    [Fact]
    public async Task MissingExpiry_IsRejected()
    {
        var token = ValidToken();
        token.Payload.ExpiresAt = null;

        await AssertRejects(token);
    }

    /// <summary>
    /// Steps 4 and 5: a present azp naming a different party says the token was minted for somebody
    /// else.
    /// </summary>
    [Fact]
    public async Task AuthorizedPartyNamingAnotherClient_IsRejected()
    {
        var token = ValidToken();
        token.Payload.AuthorizedParty = "another-client";

        await AssertRejects(token);
    }

    /// <summary>
    /// And the same claim naming this client passes, so the rejection above is about whose name it
    /// carries rather than about the claim being there at all. Absence is covered by the baseline
    /// case, since section 2 makes azp OPTIONAL.
    /// </summary>
    [Fact]
    public async Task AuthorizedPartyNamingThisClient_IsAccepted()
    {
        var token = ValidToken();
        token.Payload.AuthorizedParty = ClientId;
        var jwt = await Issue(token);

        await CreateValidator().ValidateAsync(
            jwt, new IdentityTokenValidationContext(), TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Step 11: when the client sent a nonce, the token's value MUST be the one it sent.
    /// </summary>
    [Fact]
    public async Task NonceThatDoesNotMatch_IsRejected()
    {
        var token = ValidToken();
        token.Payload.Nonce = "a-different-nonce";

        await AssertRejects(token, new IdentityTokenValidationContext { Nonce = "the-nonce-we-sent" });
    }

    /// <summary>
    /// A nonce that was asked for and did not come back is the same failure: the token is not tied to
    /// this login, which is exactly what a replayed one looks like.
    /// </summary>
    [Fact]
    public async Task MissingNonceWhenOneWasSent_IsRejected()
        => await AssertRejects(ValidToken(), new IdentityTokenValidationContext { Nonce = "the-nonce-we-sent" });

    /// <summary>
    /// A client that sent no nonce has nothing to compare against, so a nonce it never asked for is
    /// not evidence of anything and is left alone rather than treated as a mismatch.
    /// </summary>
    /// <remarks>
    /// The tempting shortcut is to compare whenever the claim is present, which would reject this
    /// token for disagreeing with a nonce that was never sent.
    /// </remarks>
    [Fact]
    public async Task NonceReturnedThoughNoneWasSent_IsAccepted()
    {
        var token = ValidToken();
        token.Payload.Nonce = "a-nonce-we-never-asked-for";
        var jwt = await Issue(token);

        await CreateValidator().ValidateAsync(
            jwt, new IdentityTokenValidationContext(), TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Section 3.2.2.9: the at_hash MUST match the hash of the access token that arrived with it.
    /// This is the check that catches a swapped access token.
    /// </summary>
    [Fact]
    public async Task AccessTokenHashThatDoesNotMatch_IsRejected()
    {
        var token = ValidToken();
        token.Payload.AccessTokenHash = HashCalculator.Compute(SigningAlgorithms.RS256, "a-different-token");

        await AssertRejects(token, new IdentityTokenValidationContext { AccessToken = "the-token-we-received" });
    }

    [Fact]
    public async Task AccessTokenHashThatMatches_IsAccepted()
    {
        const string accessToken = "the-token-we-received";
        var token = ValidToken();
        token.Payload.AccessTokenHash = HashCalculator.Compute(SigningAlgorithms.RS256, accessToken);

        var jwt = await Issue(token);

        await CreateValidator().ValidateAsync(
            jwt,
            new IdentityTokenValidationContext { AccessToken = accessToken },
            TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Section 3.3.2.10, the same construction for the authorization code - the check that closes code
    /// substitution in the hybrid flow.
    /// </summary>
    [Fact]
    public async Task CodeHashThatDoesNotMatch_IsRejected()
    {
        var token = ValidToken();
        token.Payload.CodeHash = HashCalculator.Compute(SigningAlgorithms.RS256, "a-different-code");

        await AssertRejects(token, new IdentityTokenValidationContext { AuthorizationCode = "the-code-we-received" });
    }

    /// <summary>
    /// Step 13: with max_age sent, an authentication older than it was asked for is refused.
    /// </summary>
    [Fact]
    public async Task AuthenticationOlderThanMaxAge_IsRejected()
    {
        var token = ValidToken();
        token.Payload.AuthenticationTime = TimeProvider.System.GetUtcNow().AddHours(-2);

        await AssertRejects(token, new IdentityTokenValidationContext { MaxAge = TimeSpan.FromMinutes(30) });
    }

    /// <summary>
    /// Section 2 makes auth_time REQUIRED once max_age is sent, so its absence is the provider
    /// ignoring the request - not something to pass over.
    /// </summary>
    [Fact]
    public async Task MissingAuthenticationTimeWhenMaxAgeWasSent_IsRejected()
        => await AssertRejects(ValidToken(), new IdentityTokenValidationContext { MaxAge = TimeSpan.FromMinutes(30) });

    /// <summary>
    /// Step 12: an asserted authentication context class outside what the caller accepts.
    /// </summary>
    [Fact]
    public async Task UnacceptableAuthenticationContextClass_IsRejected()
    {
        var token = ValidToken();
        token.Payload.AuthContextClassRef = "urn:mace:incommon:iap:bronze";

        await AssertRejects(
            token,
            new IdentityTokenValidationContext
            {
                AcceptableAuthenticationContextClassReferences = ["urn:mace:incommon:iap:silver"],
            });
    }

    /// <summary>
    /// A signature from a key the provider does not publish. The most basic forgery, and the reason
    /// this client declines the step-6 permission to skip signature validation on the token endpoint.
    /// </summary>
    [Fact]
    public async Task SignatureFromAnUnpublishedKey_IsRejected()
        => await AssertRejects(ValidToken(), signingKey: OtherKey);

    /// <summary>
    /// An algorithm outside what this client registered for. Accepting one because the provider
    /// advertises it is how algorithm substitution succeeds.
    /// </summary>
    [Fact]
    public async Task AlgorithmOutsideThePolicy_IsRejected()
    {
        var token = ValidToken();
        token.Header.Algorithm = SigningAlgorithms.RS512;

        await AssertRejects(
            token, configureProvider: o => o.AllowedSigningAlgorithms = [SigningAlgorithms.RS256]);
    }

    /// <summary>
    /// Step 10 is a MAY, so the age of issuance is judged only once a window is configured.
    /// </summary>
    [Fact]
    public async Task IssuedTooLongAgo_IsRejectedOnlyWhenAWindowIsSet()
    {
        var token = ValidToken();
        token.Payload.IssuedAt = TimeProvider.System.GetUtcNow().AddHours(-3);
        var jwt = await Issue(token);

        // Default policy: no window, so the age is not this client's business.
        await CreateValidator().ValidateAsync(
            jwt, new IdentityTokenValidationContext(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<IdentityTokenValidationException>(
            () => CreateValidator(o => o.MaximumIssuedAtAge = TimeSpan.FromHours(1))
                .ValidateAsync(jwt, new IdentityTokenValidationContext(), TestContext.Current.CancellationToken));
    }
}
