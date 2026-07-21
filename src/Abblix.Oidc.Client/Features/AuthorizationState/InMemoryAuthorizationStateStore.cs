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
///
/// It is also worth being plain about what this store does NOT establish, because the same cookie-backed
/// store is what closes it. Entries live in a dictionary keyed by the state value alone, so a login is
/// bound to this PROCESS and not to the browser that started it. Anyone holding a genuine, unconsumed
/// state can therefore have any browser present it: the entry is found, the nonce matches, the code
/// verifier is the right one, and the client signs that browser into the account the login was started
/// for. That is login CSRF, and RFC 9700 section 2.1 states the duty it breaches - "Clients MUST prevent
/// Cross-Site Request Forgery (CSRF)".
///
/// Neither of the two ways that section offers is available here. Its fallback wants "one-time use CSRF
/// tokens carried in the state parameter that are securely bound to the user agent", and section 2.1.1
/// closes the other route just as firmly: "In any case, the PKCE challenge or OpenID Connect nonce MUST
/// be transaction-specific and securely bound to the client and the user agent in which the transaction
/// was started." PKCE does not exempt a client from the binding - the binding is what PKCE's CSRF
/// property rests on. This package cannot supply it, having no notion of a user agent at all; a store
/// that keys on something only the right browser can present is what does, which is why the adapter's is
/// not merely the multi-replica answer but the one that makes the flow correct.
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
    public Task StoreAsync(AuthorizationContext state, CancellationToken cancellationToken = default)
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
    public Task<AuthorizationContext?> FindAsync(string state, CancellationToken cancellationToken = default)
    {
        // A read, never a removal: an entry looked up here may still be refused by a later check, and
        // removing it now would spend a login the response has not yet earned.
        if (!_states.TryGetValue(state, out var stored) || _timeProvider.GetUtcNow() >= stored.ExpiresAt)
            return Task.FromResult<AuthorizationContext?>(null);

        return Task.FromResult<AuthorizationContext?>(stored.State);
    }

    /// <inheritdoc />
    public Task<bool> RemoveAsync(string state, CancellationToken cancellationToken = default)
    {
        if (!_states.TryRemove(state, out var stored))
            return Task.FromResult(false);

        // An entry removed past its lifetime does not count as a live spend: it was already dead, and a
        // race that removed it is not the winner of a genuine callback.
        return Task.FromResult(_timeProvider.GetUtcNow() < stored.ExpiresAt);
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

    private sealed record StoredState(AuthorizationContext State, DateTimeOffset ExpiresAt);
}
