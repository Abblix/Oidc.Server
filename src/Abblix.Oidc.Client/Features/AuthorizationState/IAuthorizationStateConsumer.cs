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
/// Matches an authorization response to the login that started it, consuming the stored state so the
/// same response cannot be used twice.
/// </summary>
public interface IAuthorizationStateConsumer
{
    /// <summary>
    /// Finds and removes the state named by <paramref name="state"/>, or throws
    /// <see cref="AuthorizationStateException"/> when there is nothing to match.
    /// </summary>
    /// <param name="state">The <c>state</c> value the provider echoed, or <see langword="null"/>
    /// when the response carried none.</param>
    /// <param name="cancellationToken">Cancels the store read.</param>
    /// <returns>The state put aside when the request was built.</returns>
    /// <remarks>
    /// This is the CSRF check RFC 6749 section 10.12 asks of the redirection endpoint, in the form a
    /// client that always sends <c>state</c> can make it: a response is acted on only if it names a
    /// login this client is holding. The consuming half is as load-bearing as the matching half - a
    /// state is good for exactly one callback, so a captured response replayed a second time finds its
    /// state already gone (RFC 9700 section 4.7 treats authorization-response replay as a threat to
    /// close, not merely tidiness).
    /// It is the whole of neither CSRF defence, though. Whether the matched login belongs to the
    /// browser now presenting it is a question this contract cannot ask - it belongs to the store, and
    /// the base package's default one does not answer it. See
    /// <see cref="IAuthorizationStateStore"/>.
    /// </remarks>
    Task<AuthorizationState> ConsumeAsync(string? state, CancellationToken cancellationToken = default);
}
