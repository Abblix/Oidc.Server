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

using Abblix.Oidc.Client.Features.ClientAuthentication;
using Abblix.Oidc.Client.Features.DeviceAuthorization;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.Tokens;
using Abblix.Oidc.Client.UnitTests.Features.Discovery;
using Microsoft.Extensions.Time.Testing;

namespace Abblix.Oidc.Client.UnitTests.Features.DeviceAuthorization;

/// <summary>
/// The polling rules of RFC 8628 section 3.5, on a clock the test controls.
/// </summary>
/// <remarks>
/// These are the one part of the device grant a provider cannot be asked to demonstrate on cue: a real
/// exchange answers <c>authorization_pending</c> only while a real person hesitates, and <c>slow_down</c>
/// only when it decides the client is asking too often. So the provider is scripted here and the clock is
/// stopped, which also means the suite does not sit through the intervals it is asserting about.
/// </remarks>
public class DevicePollingTests
{
    private static readonly DateTimeOffset Start = new(2026, 7, 22, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// A token endpoint that answers from a script and records when each attempt was made.
    /// </summary>
    private sealed class ScriptedTokenEndpoint(TimeProvider clock, params string?[] script)
        : ITokenRequestService
    {
        private int _attempt;

        /// <summary>
        /// The moment of each attempt, so a test can assert the gaps rather than merely the count.
        /// </summary>
        public List<DateTimeOffset> Attempts { get; } = [];

        public Task<TokenResponse> RedeemDeviceCodeAsync(
            string deviceCode, CancellationToken cancellationToken = default)
        {
            Attempts.Add(clock.GetUtcNow());

            var error = _attempt < script.Length ? script[_attempt] : null;
            _attempt++;

            return error is null
                ? Task.FromResult(new TokenResponse { AccessToken = "the-access-token", TokenType = "Bearer" })
                : throw new TokenRequestException($"refused with '{error}'.", error, null);
        }

        public Task<TokenResponse> ExchangeCodeAsync(
            string code, string codeVerifier, string redirectUri, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<TokenResponse> RefreshAsync(
            string refreshToken, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<TokenResponse> RequestClientCredentialsAsync(
            IReadOnlyCollection<string>? scopes = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<TokenResponse> ExchangeTokenAsync(
            TokenExchangeParameters exchange, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<TokenResponse> RedeemAuthenticationRequestAsync(
            string authenticationRequestId, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private static DeviceAuthorizationResponse Authorization(int? interval = null, int expiresIn = 900) => new()
    {
        DeviceCode = "the-device-code",
        UserCode = "WDJB-MJHT",
        VerificationUri = "https://provider.example.com/device",
        ExpiresIn = expiresIn,
        Interval = interval,
    };

    private static (IDeviceAuthorizationService Service, ScriptedTokenEndpoint Endpoint, FakeTimeProvider Clock)
        Create(params string?[] script)
    {
        var clock = new FakeTimeProvider(Start);
        var endpoint = new ScriptedTokenEndpoint(clock, script);

        var service = new DeviceAuthorizationService(
            new ConfiguredMetadataProvider(new ProviderMetadata { Issuer = "https://provider.example.com" }),
            new StubHttpClientFactory(new StubHttpMessageHandler("{}")),
            new ClientCredentialsPresenter(
                Microsoft.Extensions.Options.Options.Create(new OidcClientOptions { ClientId = "test-client" }),
                Microsoft.Extensions.Options.Options.Create(new ClientAuthenticationOptions
                {
                    Method = ClientAuthenticationMethods.None,
                })),
            endpoint,
            clock);

        return (service, endpoint, clock);
    }

    /// <summary>
    /// Drives the stopped clock forward until the operation finishes, so the waiting inside it is simulated
    /// rather than endured.
    /// </summary>
    /// <remarks>
    /// Bounded on purpose: a loop that advanced until completion would hang rather than fail if the code
    /// under test never stopped polling, which is one of the defects these tests exist to catch.
    /// </remarks>
    private static async Task<T> RunAsync<T>(Task<T> operation, FakeTimeProvider clock)
    {
        for (var second = 0; second < 3600 && !operation.IsCompleted; second++)
        {
            clock.Advance(TimeSpan.FromSeconds(1));
            await Task.Yield();
        }

        Assert.True(operation.IsCompleted, "The device polling did not finish within the exchange's lifetime.");
        return await operation;
    }

    /// <summary>
    /// The client waits before asking at all, and keeps waiting the interval the provider named while its
    /// user is still deciding.
    /// </summary>
    [Fact]
    public async Task ThePollingKeepsTheIntervalTheProviderNamed()
    {
        var (service, endpoint, clock) = Create(TokenErrorCodes.AuthorizationPending, TokenErrorCodes.AuthorizationPending);

        var response = await RunAsync(
            service.WaitForTokensAsync(Authorization(interval: 7), TestContext.Current.CancellationToken),
            clock);

        Assert.Equal("the-access-token", response.AccessToken);
        Assert.Equal(3, endpoint.Attempts.Count);
        Assert.Equal(Start.AddSeconds(7), endpoint.Attempts[0]);
        Assert.Equal(Start.AddSeconds(14), endpoint.Attempts[1]);
        Assert.Equal(Start.AddSeconds(21), endpoint.Attempts[2]);
    }

    /// <summary>
    /// A provider that names no interval is polled every five seconds, which RFC 8628 section 3.2 states as
    /// a requirement on the client rather than a suggestion.
    /// </summary>
    [Fact]
    public async Task AProviderThatNamesNoIntervalIsPolledEveryFiveSeconds()
    {
        var (service, endpoint, clock) = Create(TokenErrorCodes.AuthorizationPending);

        await RunAsync(
            service.WaitForTokensAsync(Authorization(), TestContext.Current.CancellationToken),
            clock);

        Assert.Equal(Start.AddSeconds(5), endpoint.Attempts[0]);
        Assert.Equal(Start.AddSeconds(10), endpoint.Attempts[1]);
    }

    /// <summary>
    /// A <c>slow_down</c> adds five seconds to the interval and keeps them: section 3.5 says the increase is
    /// "for this and all subsequent requests".
    /// </summary>
    /// <remarks>
    /// The lasting part is what this asserts, and it is the half that gets written wrong. A client that
    /// waited longer only once and then went back to the old interval would look correct on the next poll
    /// and be asking too often again by the one after.
    /// </remarks>
    [Fact]
    public async Task ASlowDownRaisesTheIntervalForGood()
    {
        var (service, endpoint, clock) = Create(
            TokenErrorCodes.SlowDown, TokenErrorCodes.AuthorizationPending, TokenErrorCodes.AuthorizationPending);

        await RunAsync(
            service.WaitForTokensAsync(Authorization(interval: 5), TestContext.Current.CancellationToken),
            clock);

        Assert.Equal(4, endpoint.Attempts.Count);
        Assert.Equal(Start.AddSeconds(5), endpoint.Attempts[0]);
        Assert.Equal(Start.AddSeconds(15), endpoint.Attempts[1]);
        Assert.Equal(Start.AddSeconds(25), endpoint.Attempts[2]);
        Assert.Equal(Start.AddSeconds(35), endpoint.Attempts[3]);
    }

    /// <summary>
    /// A user who refuses the device ends the exchange at once: section 3.5 has the client stop polling on
    /// any error other than the two that mean "not yet".
    /// </summary>
    [Fact]
    public async Task ARefusalByTheUserStopsThePolling()
    {
        var (service, endpoint, clock) = Create(TokenErrorCodes.AccessDenied);

        var exception = await Assert.ThrowsAsync<TokenRequestException>(
            () => RunAsync(
                service.WaitForTokensAsync(Authorization(interval: 5), TestContext.Current.CancellationToken),
                clock));

        Assert.Equal(TokenErrorCodes.AccessDenied, exception.Error);
        Assert.Single(endpoint.Attempts);
    }

    /// <summary>
    /// Polling stops when the exchange's own lifetime runs out, whether or not the provider has said so.
    /// </summary>
    /// <remarks>
    /// The provider is expected to answer <c>expired_token</c>, and this client does not depend on it: a
    /// device left running against a provider that keeps answering <c>authorization_pending</c> past the
    /// stated lifetime would otherwise poll for as long as it stays switched on.
    /// </remarks>
    [Fact]
    public async Task PollingStopsWhenTheExchangeHasExpired()
    {
        var (service, endpoint, clock) = Create(
            Enumerable.Repeat<string?>(TokenErrorCodes.AuthorizationPending, 100).ToArray());

        var exception = await Assert.ThrowsAsync<TokenRequestException>(
            () => RunAsync(
                service.WaitForTokensAsync(
                    Authorization(interval: 5, expiresIn: 30), TestContext.Current.CancellationToken),
                clock));

        Assert.Equal(TokenErrorCodes.ExpiredToken, exception.Error);

        // Five, not six: the thirty-second lifetime allows polls at 5, 10, 15, 20 and 25 seconds, and the
        // one falling exactly on the expiry is not made. A code is expired at the instant it expires, so
        // presenting it then would be asking for a refusal the client can already predict.
        Assert.Equal(5, endpoint.Attempts.Count);
    }
}
