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

using Abblix.Oidc.Client.Features.Authorization.Context;

namespace Abblix.Oidc.Client.Features.Authorization.Responses;

/// <summary>
/// Takes an authorization response from the callback address through every check, in order, and hands
/// back the authorization code when it survives them.
/// </summary>
public interface IAuthorizationResponseHandler
{
    /// <summary>
    /// Parses, verifies, and consumes the response named by <paramref name="parameters"/>, returning
    /// what it carried, or throwing when the response must not be acted on.
    /// </summary>
    /// <param name="parameters">
    /// The parameters as delivered to the callback address, each name mapped to every value that
    /// arrived under it - built by the adapter from a query string, a posted form, or wherever it got
    /// them, so this contract needs no HTTP type.
    /// </param>
    /// <param name="cancellationToken">Cancels the store and metadata reads this makes.</param>
    /// <returns>The authorization code and the consumed state, ready for the token exchange.</returns>
    /// <exception cref="AuthorizationResponseException">
    /// The provider refused (the exception carries the error code), or the response was one this client
    /// refused - a wrong issuer, a shape no specification defines, a parameter that arrived twice.
    /// </exception>
    /// <exception cref="AuthorizationStateException">
    /// The response matched no login this client is holding.
    /// </exception>
    /// <remarks>
    /// The order the checks run in is the substance of this type, not an implementation detail. A
    /// response that arrives is untrusted input, and each step is a gate the next depends on: nothing
    /// about the provider's answer - not even whether it was a success or a failure worth logging - is
    /// acted on until the response is known to have come from the provider this login was started with.
    /// </remarks>
    Task<AuthorizationResult> HandleAsync(
        IReadOnlyDictionary<string, IReadOnlyList<string>> parameters,
        CancellationToken cancellationToken = default);
}
