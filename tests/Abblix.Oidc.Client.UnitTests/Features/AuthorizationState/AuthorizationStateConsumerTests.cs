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
using State = Abblix.Oidc.Client.Features.AuthorizationState.AuthorizationState;

namespace Abblix.Oidc.Client.UnitTests.Features.AuthorizationState;

/// <summary>
/// Matching an authorization response to the login that started it, and the shapes of a miss.
/// </summary>
public class AuthorizationStateConsumerTests
{
    private static State StateFor(string state) => new()
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
    /// A response naming a held state gets it back, with everything the request put aside.
    /// </summary>
    [Fact]
    public async Task ConsumesAHeldState()
    {
        var (consumer, store) = Create();
        await store.StoreAsync(StateFor("the-state"), TestContext.Current.CancellationToken);

        var consumed = await consumer.ConsumeAsync("the-state", TestContext.Current.CancellationToken);

        Assert.Equal("the-nonce", consumed.Nonce);
        Assert.Equal("the-verifier", consumed.CodeVerifier);
    }

    /// <summary>
    /// The second attempt on the same state finds nothing, which is what makes a replayed response fail.
    /// RFC 9700 section 4.7 counts authorization-response replay as a threat to close.
    /// </summary>
    [Fact]
    public async Task ConsumingTwice_FailsTheSecondTimeAsUnknown()
    {
        var (consumer, store) = Create();
        await store.StoreAsync(StateFor("the-state"), TestContext.Current.CancellationToken);

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
            () => consumer.ConsumeAsync("never-issued", TestContext.Current.CancellationToken));

        Assert.Equal(AuthorizationStateFailure.Unknown, error.Failure);
    }

    /// <summary>
    /// No state at all is a distinct failure, because this client sends one on every request, so its
    /// absence cannot be an expired login to restart.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task NoState_IsMissing(string? state)
    {
        var (consumer, _) = Create();

        var error = await Assert.ThrowsAsync<AuthorizationStateException>(
            () => consumer.ConsumeAsync(state, TestContext.Current.CancellationToken));

        Assert.Equal(AuthorizationStateFailure.Missing, error.Failure);
    }

    /// <summary>
    /// A state that expired before the response arrived reads as Unknown, indistinguishable from a
    /// forged one - which is the point. The store drops an entry older than its lifetime, so the
    /// consumer never sees it.
    /// </summary>
    [Fact]
    public async Task AnExpiredState_IsUnknown()
    {
        var time = new FakeTimeProvider();
        var store = new InMemoryAuthorizationStateStore(
            time, Options.Create(new AuthorizationStateOptions { Lifetime = TimeSpan.FromMinutes(15) }));
        var consumer = new AuthorizationStateConsumer(store);

        await store.StoreAsync(StateFor("the-state"), TestContext.Current.CancellationToken);
        time.Advance(TimeSpan.FromMinutes(16));

        var error = await Assert.ThrowsAsync<AuthorizationStateException>(
            () => consumer.ConsumeAsync("the-state", TestContext.Current.CancellationToken));

        Assert.Equal(AuthorizationStateFailure.Unknown, error.Failure);
    }
}
