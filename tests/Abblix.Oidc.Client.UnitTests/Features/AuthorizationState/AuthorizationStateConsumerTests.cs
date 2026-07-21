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

using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

using Abblix.Oidc.Client.Features.AuthorizationState;

namespace Abblix.Oidc.Client.UnitTests.Features.AuthorizationState;

/// <summary>
/// Matching an authorization response to the login that started it, and the shapes of a miss.
/// </summary>
public class AuthorizationStateConsumerTests
{
    private static AuthorizationContext ContextFor(string state) => new()
    {
        State = state,
        Nonce = "the-nonce",
        CodeVerifier = "the-verifier",
        ReturnUri = "/orders",
        Issuer = "https://provider.example.com",
        RedirectUri = "https://client.example.com/signin-oidc",
    };

    private static (IAuthorizationStateConsumer Consumer, IAuthorizationStateStore Store) Create()
    {
        var store = new InMemoryAuthorizationStateStore(
            new FakeTimeProvider(), Options.Create(new AuthorizationStateOptions()));

        return (new AuthorizationStateConsumer(store), store);
    }

    /// <summary>
    /// Finding a held state returns it, with everything the request put aside, and leaves it in place.
    /// </summary>
    [Fact]
    public async Task FindsAHeldState_WithoutSpendingIt()
    {
        var (consumer, store) = Create();
        await store.StoreAsync(ContextFor("the-state"), TestContext.Current.CancellationToken);

        var found = await consumer.FindAsync("the-state", TestContext.Current.CancellationToken);

        Assert.Equal("the-nonce", found.Nonce);
        Assert.Equal("the-verifier", found.CodeVerifier);

        // Still held: finding is a look-up, so a response that fails a later check has not spent it.
        Assert.NotNull(await store.FindAsync("the-state", TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// After the state is spent, the same one cannot be spent again - the second attempt is the replay
    /// this refuses. RFC 9700 section 4.7 counts authorization-response replay as a threat to close.
    /// </summary>
    [Fact]
    public async Task ConsumingTwice_FailsTheSecondTimeAsUnknown()
    {
        var (consumer, store) = Create();
        await store.StoreAsync(ContextFor("the-state"), TestContext.Current.CancellationToken);

        await consumer.ConsumeAsync("the-state", TestContext.Current.CancellationToken);

        var error = await Assert.ThrowsAsync<AuthorizationStateException>(
            () => consumer.ConsumeAsync("the-state", TestContext.Current.CancellationToken));

        Assert.Equal(AuthorizationStateFailure.Unknown, error.Failure);
    }

    /// <summary>
    /// A state this client never issued is the same Unknown as an expired or replayed one - the three
    /// are deliberately not told apart.
    /// </summary>
    [Fact]
    public async Task AStateThatWasNeverIssued_IsUnknown()
    {
        var (consumer, _) = Create();

        var error = await Assert.ThrowsAsync<AuthorizationStateException>(
            () => consumer.FindAsync("never-issued", TestContext.Current.CancellationToken));

        Assert.Equal(AuthorizationStateFailure.Unknown, error.Failure);
    }

    /// <summary>
    /// No state at all is a distinct failure, because this client sends one on every request, so its
    /// absence cannot be an expired login to restart. The look-up is where it surfaces.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task NoState_IsMissing(string? state)
    {
        var (consumer, _) = Create();

        var error = await Assert.ThrowsAsync<AuthorizationStateException>(
            () => consumer.FindAsync(state, TestContext.Current.CancellationToken));

        Assert.Equal(AuthorizationStateFailure.Missing, error.Failure);
    }

    /// <summary>
    /// A state that expired before the response arrived reads as Unknown, indistinguishable from a
    /// forged one - which is the point. The store drops an entry older than its lifetime, so the
    /// consumer never finds it.
    /// </summary>
    [Fact]
    public async Task AnExpiredState_IsUnknown()
    {
        var time = new FakeTimeProvider();
        var store = new InMemoryAuthorizationStateStore(
            time, Options.Create(new AuthorizationStateOptions { Lifetime = TimeSpan.FromMinutes(15) }));
        var consumer = new AuthorizationStateConsumer(store);

        await store.StoreAsync(ContextFor("the-state"), TestContext.Current.CancellationToken);
        time.Advance(TimeSpan.FromMinutes(16));

        var error = await Assert.ThrowsAsync<AuthorizationStateException>(
            () => consumer.FindAsync("the-state", TestContext.Current.CancellationToken));

        Assert.Equal(AuthorizationStateFailure.Unknown, error.Failure);
    }
}
