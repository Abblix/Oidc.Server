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

using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Client.Features.BackChannelLogout;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.SigningKeys;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.UnitTests.Features.BackChannelLogout;

/// <summary>
/// The validation steps of OpenID Connect Back-Channel Logout 1.0 section 2.6, one case each, against
/// tokens this suite signs itself so every check can be attacked in isolation.
/// </summary>
/// <remarks>
/// Each rejection case changes exactly one thing about a token that otherwise validates, so a passing test
/// says the named check did the rejecting rather than something incidental.
/// </remarks>
public class LogoutTokenValidatorTests
{
    private const string Issuer = "https://auth.example.com";
    private const string ClientId = "test-client";
    private const string Subject = "248289761001";

    private sealed class StubMetadataProvider : IProviderMetadataProvider
    {
        public Task<ProviderMetadata> GetMetadataAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new ProviderMetadata { Issuer = Issuer });
    }

    /// <summary>
    /// Publishes exactly the key the suite signs with, so a token signed by any other key is a forgery by
    /// construction rather than by configuration.
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
            Subject = Subject,
            JwtId = "logout-token-id",
            IssuedAt = TimeProvider.System.GetUtcNow(),
            ExpiresAt = TimeProvider.System.GetUtcNow().AddMinutes(2),
            [JwtClaimTypes.Events] = new JsonObject
            {
                [LogoutTokenClaims.BackChannelLogoutEvent] = new JsonObject(),
            },
        },
    };

    private static Task<string> Issue(JsonWebToken token, JsonWebKey? key = null)
        => Jwt.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, key ?? SigningKey);

    private static ILogoutTokenValidator CreateValidator()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IProviderMetadataProvider>(new StubMetadataProvider());
        services.AddSingleton<IIssuerSigningKeysProvider>(new StubSigningKeysProvider(SigningKey));
        services.Configure<OidcClientOptions>(o => o.ClientId = ClientId);
        services.AddBackChannelLogout();

        return services.BuildServiceProvider().GetRequiredService<ILogoutTokenValidator>();
    }

    private static async Task<LogoutNotification> Validate(JsonWebToken token, JsonWebKey? signingKey = null)
        => await CreateValidator().ValidateAsync(
            await Issue(token, signingKey), TestContext.Current.CancellationToken);

    private static async Task<LogoutTokenValidationException> AssertRejects(
        JsonWebToken token, JsonWebKey? signingKey = null)
        => await Assert.ThrowsAsync<LogoutTokenValidationException>(() => Validate(token, signingKey));

    /// <summary>
    /// A token satisfying every step is accepted, and says which sessions to end. Without this case every
    /// rejection below could be a token that was broken all along.
    /// </summary>
    [Fact]
    public async Task ValidToken_IsAccepted()
    {
        var notification = await Validate(ValidToken());

        Assert.Equal(Issuer, notification.Issuer);
        Assert.Equal(Subject, notification.Subject);
        Assert.Equal("logout-token-id", notification.TokenId);
        Assert.Null(notification.SessionId);
    }

    /// <summary>
    /// A session identifier is carried through when the token names one. Section 2.7 asks the RP to
    /// "locate the session(s) identified by the iss and sub Claims and/or the sid Claim", so both forms
    /// have to reach the host.
    /// </summary>
    [Fact]
    public async Task ASessionIdentifierIsCarriedThrough()
    {
        var token = ValidToken();
        token.Payload.SessionId = "the-session";

        var notification = await Validate(token);

        Assert.Equal("the-session", notification.SessionId);
    }

    /// <summary>
    /// Step 5 is satisfied by a sid alone: "Verify that the Logout Token contains a sub Claim, a sid Claim,
    /// or both."
    /// </summary>
    [Fact]
    public async Task ASessionIdentifierAloneIsEnough()
    {
        var token = ValidToken();
        token.Payload.Subject = null;
        token.Payload.SessionId = "the-session";

        var notification = await Validate(token);

        Assert.Null(notification.Subject);
        Assert.Equal("the-session", notification.SessionId);
    }

    /// <summary>
    /// Step 5, the other way: a token naming neither says a session ended without saying whose, leaving
    /// section 2.7 nothing to locate.
    /// </summary>
    [Fact]
    public async Task NeitherSubjectNorSession_IsRejected()
    {
        var token = ValidToken();
        token.Payload.Subject = null;

        await AssertRejects(token);
    }

    /// <summary>
    /// Step 6: without the events claim naming the back-channel logout event, this is some other token the
    /// same issuer signed for the same audience. An ID Token above all, which is the cross-JWT confusion of
    /// section 4.1.
    /// </summary>
    [Fact]
    public async Task NoEventsClaim_IsRejected()
    {
        var token = ValidToken();
        token.Payload[JwtClaimTypes.Events] = null;

        await AssertRejects(token);
    }

    /// <summary>
    /// Step 6 again: an events claim naming some other event is not a logout notification.
    /// </summary>
    [Fact]
    [SuppressMessage("SonarQube", "S5332:Using http protocol is insecure",
        Justification = "Not a URL to fetch: an event identifier in the http://schemas.openid.net/event/ "
            + "namespace OpenID Connect Back-Channel Logout 1.0 section 2.4 uses, standing in here for one "
            + "that is not the logout event, to prove it is rejected.")]
    public async Task AnotherEvent_IsRejected()
    {
        var token = ValidToken();
        token.Payload[JwtClaimTypes.Events] = new JsonObject
        {
            ["http://schemas.openid.net/event/something-else"] = new JsonObject(),
        };

        await AssertRejects(token);
    }

    /// <summary>
    /// Step 6, malformed rather than missing: section 2.4 requires the events value to be a JSON object,
    /// so a string that happens to name the event is refused rather than searched.
    /// </summary>
    [Fact]
    public async Task AnEventsClaimThatIsNotAnObject_IsRejected()
    {
        var token = ValidToken();
        token.Payload[JwtClaimTypes.Events] = LogoutTokenClaims.BackChannelLogoutEvent;

        await AssertRejects(token);
    }

    /// <summary>
    /// Step 7: "Verify that the Logout Token does not contain a nonce Claim." Section 2.4 gives the reason,
    /// and it runs the other way round - the prohibition exists so that a Logout Token cannot be passed off
    /// as an ID Token in a forged authentication response.
    /// </summary>
    [Fact]
    public async Task ANonce_IsRejected()
    {
        var token = ValidToken();
        token.Payload.Nonce = "n-0S6_WzA2Mj";

        await AssertRejects(token);
    }

    /// <summary>
    /// Step 2, by reference to ID Token validation: a token signed by a key the provider does not publish
    /// is a forgery. This is the check the whole endpoint rests on, since the request carrying the token is
    /// unauthenticated and anyone on the network can make it.
    /// </summary>
    [Fact]
    public async Task AnUnknownSigningKey_IsRejected()
        => await AssertRejects(ValidToken(), OtherKey);

    /// <summary>
    /// Step 4, by reference: another issuer's token is refused however well formed it is.
    /// </summary>
    [Fact]
    public async Task AnotherIssuer_IsRejected()
    {
        var token = ValidToken();
        token.Payload.Issuer = "https://evil.example.com";

        await AssertRejects(token);
    }

    /// <summary>
    /// Step 4, by reference: a token addressed to another client would log this client's user out on
    /// somebody else's say-so.
    /// </summary>
    [Fact]
    public async Task AnotherAudience_IsRejected()
    {
        var token = ValidToken();
        token.Payload.Audiences = ["another-client"];

        await AssertRejects(token);
    }

    /// <summary>
    /// Step 4, by reference: an expired token is refused. Section 4 asks providers to keep the window
    /// short, "preferably at most two minutes in the future, to prevent captured Logout Tokens from being
    /// replayable", which only helps if the recipient enforces it.
    /// </summary>
    [Fact]
    public async Task AnExpiredToken_IsRejected()
    {
        var token = ValidToken();
        token.Payload.IssuedAt = TimeProvider.System.GetUtcNow().AddHours(-2);
        token.Payload.ExpiresAt = TimeProvider.System.GetUtcNow().AddHours(-1);

        await AssertRejects(token);
    }

    /// <summary>
    /// Step 8: the same token acted on twice is a replay the second time. The request carrying it is
    /// unauthenticated, so anyone who observed it can post it again inside the short window section 4 asks
    /// providers to use.
    /// </summary>
    [Fact]
    public async Task AReplayedToken_IsRejected()
    {
        var validator = CreateValidator();
        var jwt = await Issue(ValidToken());

        await validator.ValidateAsync(jwt, TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<LogoutTokenValidationException>(
            () => validator.ValidateAsync(jwt, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A token carrying no identifier cannot be told apart from a replay of itself, so taking step 8 at all
    /// means refusing it. Section 2.4 lists jti among the REQUIRED claims; the refusal is ours.
    /// </summary>
    [Fact]
    public async Task NoTokenIdentifier_IsRejected()
    {
        var token = ValidToken();
        token.Payload.JwtId = null;

        await AssertRejects(token);
    }
}
