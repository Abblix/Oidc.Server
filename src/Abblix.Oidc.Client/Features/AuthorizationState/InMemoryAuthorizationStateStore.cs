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

using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.AuthorizationState;

/// <summary>
/// Holds authorization state in the memory of one process.
/// </summary>
/// <remarks>
/// The default, and correct only for a single instance. The callback that consumes a state may land on any
/// replica, so an application running several will see sign-ins fail whenever the callback reaches a replica
/// other than the one that started the request. The ASP.NET adapter's cookie-backed store is the answer
/// there, because it travels with the user rather than living on one node.
/// </remarks>
public sealed class InMemoryAuthorizationStateStore : IAuthorizationStateStore
{
    private readonly TimeProvider _timeProvider;
    private readonly AuthorizationStateOptions _options;
    private readonly ConcurrentDictionary<string, StoredState> _states = new(StringComparer.Ordinal);

    /// <summary>
    /// Creates the store.
    /// </summary>
    public InMemoryAuthorizationStateStore(
        TimeProvider timeProvider, IOptions<AuthorizationStateOptions> options)
    {
        _timeProvider = timeProvider;
        _options = options.Value;
    }

    /// <inheritdoc />
    public Task StoreAsync(AuthorizationState state, CancellationToken cancellationToken = default)
    {
        // A sign-in that was started and never finished must not be held forever: the entries carry a code
        // verifier, and a process that only ever adds them is a slow leak driven by anyone who can start a
        // sign-in. Sweeping on write keeps that bounded without a timer.
        RemoveExpired();

        var expiresAt = _timeProvider.GetUtcNow() + _options.Lifetime;
        _states[state.State] = new StoredState(state, expiresAt);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<AuthorizationState?> TakeAsync(string state, CancellationToken cancellationToken = default)
    {
        if (!_states.TryRemove(state, out var stored))
            return Task.FromResult<AuthorizationState?>(null);

        // Removed either way: an expired entry is spent, not retryable.
        var result = _timeProvider.GetUtcNow() < stored.ExpiresAt ? stored.State : null;
        return Task.FromResult(result);
    }

    private void RemoveExpired()
    {
        var now = _timeProvider.GetUtcNow();

        foreach (var (key, stored) in _states)
        {
            if (now >= stored.ExpiresAt)
                _states.TryRemove(key, out _);
        }
    }

    private sealed record StoredState(AuthorizationState State, DateTimeOffset ExpiresAt);
}
