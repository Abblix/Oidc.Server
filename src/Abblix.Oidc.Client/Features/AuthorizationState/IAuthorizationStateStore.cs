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

namespace Abblix.Oidc.Client.Features.AuthorizationState;

/// <summary>
/// Holds the state of an authorization request between sending the user to the provider and their return.
/// </summary>
/// <remarks>
/// An implementation carries a security obligation the contract cannot express in its signatures: the
/// entry it hands back must be reachable only by the user agent the login was started in. RFC 9700
/// section 2.1.1 states it without an exit - "In any case, the PKCE challenge or OpenID Connect nonce
/// MUST be transaction-specific and securely bound to the client and the user agent in which the
/// transaction was started" - and section 2.1 asks the same of a state-based CSRF token. A store that
/// finds an entry by the state value alone satisfies neither, and lets a login started in one browser be
/// completed in another, which is login CSRF.
/// <see cref="InMemoryAuthorizationStateStore"/> is such a store, deliberately and with its limits
/// written down; a host that needs the binding supplies one keyed on something only the right browser
/// can present, which is what the ASP.NET adapter's cookie-backed store does.
/// </remarks>
public interface IAuthorizationStateStore
{
    /// <summary>
    /// Puts the state aside, keyed by its own <see cref="AuthorizationState.State"/> value.
    /// </summary>
    /// <param name="state">The state to remember.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    Task StoreAsync(AuthorizationState state, CancellationToken cancellationToken = default);

    /// <summary>
    /// Looks up the state matching the value the provider echoed, WITHOUT removing it.
    /// </summary>
    /// <param name="state">The <c>state</c> parameter from the authorization response.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The stored state, or <c>null</c> when nothing matches or it has expired.</returns>
    /// <remarks>
    /// Reading is separate from spending on purpose, and the separation is load-bearing rather than
    /// tidy. Whether the response may be acted on is decided from what this returns - the issuer it was
    /// sent to, above all - and those decisions can fail. If the lookup removed the entry, a response
    /// that fails a later check would have spent a login it was never entitled to, letting an attacker
    /// who merely knows the (non-secret) <c>state</c> value burn a victim's pending sign-in. So this
    /// only reads; <see cref="RemoveAsync"/> spends, and only once the response has earned it.
    /// </remarks>
    Task<AuthorizationState?> FindAsync(string state, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes the state matching the value, and reports whether this call is the one that removed a
    /// live entry.
    /// </summary>
    /// <param name="state">The <c>state</c> parameter from the authorization response.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns><c>true</c> when this call removed a live entry; <c>false</c> when there was none to
    /// remove or it had expired.</returns>
    /// <remarks>
    /// This is the single-use gate. A stored state is good for exactly one callback, so removal must be
    /// atomic and must report the winner: of two callbacks racing on the same state, the one that gets
    /// <c>true</c> proceeds and the one that gets <c>false</c> is a replay to refuse. That the removal
    /// runs only after the response has been checked is the caller's duty, not this method's.
    /// </remarks>
    Task<bool> RemoveAsync(string state, CancellationToken cancellationToken = default);
}
