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

namespace Abblix.Oidc.Client.Features.Authorization.Context;

/// <summary>
/// Matches an authorization response to the login that started it, consuming the stored state so the
/// same response cannot be used twice.
/// </summary>
public interface IAuthorizationStateConsumer
{
    /// <summary>
    /// Locates the held login named by <paramref name="state"/> WITHOUT spending it, or throws
    /// <see cref="AuthorizationStateException"/> when there is none to match.
    /// </summary>
    /// <param name="state">The <c>state</c> value the provider echoed, or <see langword="null"/>
    /// when the response carried none.</param>
    /// <param name="cancellationToken">Cancels the store read.</param>
    /// <returns>The state put aside when the request was built.</returns>
    /// <remarks>
    /// This is the first half of the CSRF check RFC 6749 section 10.12 asks of the redirection
    /// endpoint, in the form a client that always sends <c>state</c> can make it: a response is
    /// considered only if it names a login this client is holding. It is deliberately only a look-up.
    /// The login is not spent here, because whether the response may be acted on is decided from what
    /// this returns - the issuer it was sent to - and that decision can fail. Spending the login before
    /// the decision would let a response that fails a later check burn a sign-in it was never entitled
    /// to, which is a login denial of service for anyone who knows the (non-secret) <c>state</c> value.
    /// The second half is <see cref="ConsumeAsync"/>, run once those checks have passed.
    /// Neither half is the whole CSRF defence. Whether the matched login belongs to the browser now
    /// presenting it is a question this contract cannot ask - it belongs to the store, and the base
    /// package's default one does not answer it. See <see cref="IAuthorizationStateStore"/>.
    /// </remarks>
    Task<AuthorizationContext> FindAsync(string? state, CancellationToken cancellationToken = default);

    /// <summary>
    /// Spends the held login named by <paramref name="state"/>, so the same response cannot be acted on
    /// twice, or throws <see cref="AuthorizationStateException"/> when it was already spent.
    /// </summary>
    /// <param name="state">The <c>state</c> value, known to be non-null once
    /// <see cref="FindAsync"/> has returned.</param>
    /// <param name="cancellationToken">Cancels the store write.</param>
    /// <remarks>
    /// The single-use gate, run only after the response has earned it. A state is good for exactly one
    /// callback, so a captured response replayed a second time finds its login already spent and is
    /// refused (RFC 9700 section 4.7 treats authorization-response replay as a threat to close, not
    /// tidiness). Removal is atomic, so of two callbacks racing on one state exactly one spends it and
    /// the other is turned away here.
    /// </remarks>
    Task ConsumeAsync(string state, CancellationToken cancellationToken = default);
}
