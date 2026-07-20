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

using Abblix.Oidc.Client.Features.AuthorizationState;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Abblix.Oidc.Client.UnitTests.Features.AuthorizationState;

/// <summary>
/// Tests for <see cref="InMemoryAuthorizationStateStore"/>.
/// </summary>
public class InMemoryAuthorizationStateStoreTests
{
    private static Client.Features.AuthorizationState.AuthorizationState StateFor(string state) => new()
    {
        State = state,
        Nonce = "nonce",
        CodeVerifier = "verifier",
        ReturnUri = "https://client.example.com/orders",
        Issuer = "https://provider.example.com",
        RedirectUri = "https://client.example.com/signin-oidc",
    };

    private static InMemoryAuthorizationStateStore CreateStore(
        TimeProvider timeProvider, TimeSpan? lifetime = null)
    {
        var options = new AuthorizationStateOptions();
        if (lifetime is { } value)
            options.Lifetime = value;

        return new InMemoryAuthorizationStateStore(timeProvider, Options.Create(options));
    }

    /// <summary>
    /// What was put aside comes back, and a look-up leaves it in place.
    /// </summary>
    [Fact]
    public async Task FindReturnsWhatWasStored_AndDoesNotRemoveIt()
    {
        var store = CreateStore(new FakeTimeProvider());
        await store.StoreAsync(StateFor("first"), TestContext.Current.CancellationToken);

        var found = await store.FindAsync("first", TestContext.Current.CancellationToken);
        Assert.Equal("verifier", found?.CodeVerifier);

        // Still there: FindAsync reads without spending, so a second look-up sees it too. That the spend
        // is separate is what stops a response that fails a later check from burning a held sign-in.
        Assert.NotNull(await store.FindAsync("first", TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A state is spent exactly once. The first removal wins and reports it; a second finds nothing to
    /// remove, which is what turns a replayed callback away.
    /// </summary>
    [Fact]
    public async Task AStateIsRemovedExactlyOnce()
    {
        var store = CreateStore(new FakeTimeProvider());
        await store.StoreAsync(StateFor("first"), TestContext.Current.CancellationToken);

        Assert.True(await store.RemoveAsync("first", TestContext.Current.CancellationToken));
        Assert.False(await store.RemoveAsync("first", TestContext.Current.CancellationToken));

        // And it is gone from a look-up too.
        Assert.Null(await store.FindAsync("first", TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A state that was never issued matches nothing, which is what makes a forged callback fail.
    /// </summary>
    [Fact]
    public async Task AnUnknownStateMatchesNothing()
    {
        var store = CreateStore(new FakeTimeProvider());

        Assert.Null(await store.FindAsync("never-issued", TestContext.Current.CancellationToken));
        Assert.False(await store.RemoveAsync("never-issued", TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A sign-in that took longer than allowed is honoured by neither operation, bounding how long a
    /// captured authorization request stays useful to whoever captured it.
    /// </summary>
    [Fact]
    public async Task AStateThatOutlivedItsWindowIsNotHonoured()
    {
        var timeProvider = new FakeTimeProvider();
        var store = CreateStore(timeProvider, TimeSpan.FromMinutes(15));

        await store.StoreAsync(StateFor("first"), TestContext.Current.CancellationToken);
        timeProvider.Advance(TimeSpan.FromMinutes(16));

        Assert.Null(await store.FindAsync("first", TestContext.Current.CancellationToken));
        // Removing an entry past its lifetime is not a live spend, so it reports false.
        Assert.False(await store.RemoveAsync("first", TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Sign-ins that were started and abandoned do not accumulate. The entries carry a code verifier, so a
    /// store that only ever grows is a slow leak driven by anyone able to start a sign-in.
    /// </summary>
    [Fact]
    public async Task AbandonedSignInsDoNotAccumulate()
    {
        var timeProvider = new FakeTimeProvider();
        var store = CreateStore(timeProvider, TimeSpan.FromMinutes(15));

        await store.StoreAsync(StateFor("abandoned"), TestContext.Current.CancellationToken);
        timeProvider.Advance(TimeSpan.FromMinutes(16));

        // Storing anything sweeps what has aged out, so the abandoned entry is gone before this one is added.
        await store.StoreAsync(StateFor("current"), TestContext.Current.CancellationToken);

        Assert.Null(await store.FindAsync("abandoned", TestContext.Current.CancellationToken));
        Assert.NotNull(await store.FindAsync("current", TestContext.Current.CancellationToken));
    }
}
