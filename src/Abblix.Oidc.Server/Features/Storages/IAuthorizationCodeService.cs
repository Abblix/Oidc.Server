// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Provides a contract for managing OAuth 2.0 authorization codes, facilitating the authorization code flow.
/// This interface enables the generation of unique authorization codes for authenticated sessions, the validation
/// of these codes for user authorization, and the subsequent removal of codes once they have been used or expired,
/// ensuring adherence to the OAuth 2.0 specification.
/// </summary>
public interface IAuthorizationCodeService
{
    /// <summary>
    /// Generates a unique authorization code for a given authorization grant result and specified expiration time.
    /// The authorization code is a temporary code that the client exchanges for an access token, typically after
    /// the user has authenticated and authorized the request.
    /// </summary>
    /// <param name="authorizedGrant">An object encapsulating the result of the authorization grant, including
    /// user authentication session and authorization context details.</param>
    /// <param name="authorizationCodeExpiresIn">The duration after which the generated authorization code will expire.</param>
    /// <returns>A task that asynchronously returns the generated authorization code as a string. This code
    /// is intended for single-use and has a limited lifetime, after which it must be exchanged for an access token
    /// or considered invalid.</returns>
    Task<string> GenerateAuthorizationCodeAsync(
        AuthorizedGrant authorizedGrant,
        TimeSpan authorizationCodeExpiresIn);

    /// <summary>
    /// Validates an authorization code and processes the authorization request, authorizing the user
    /// and granting access based on the code provided. This method verifies the code's validity, ensuring it
    /// matches a previously issued code and has not expired or been used.
    /// </summary>
    /// <param name="authorizationCode">The authorization code to be validated and processed for granting access.</param>
    /// <returns>A task that asynchronously returns a <see cref="Result{AuthorizedGrant, AuthError}"/> representing the outcome
    /// of the authorization process, including any access tokens or refresh tokens issued as part of the grant.</returns>
    Task<Result<AuthorizedGrant, OidcError>> AuthorizeByCodeAsync(string authorizationCode);

    /// <summary>
    /// Atomically removes an authorization code from storage and returns the grant it held, in a
    /// single get-and-remove operation. This is how a code is claimed for redemption: it enforces
    /// the single-use guarantee against a race between two simultaneous redemptions of the same
    /// code (RFC 6749 section 4.1.2) - every other caller finds the code already gone and receives an
    /// <c>invalid_grant</c> failure.
    /// <para>
    /// One exception on a single node, and it is a loss rather than a duplication: a removal can end with
    /// NOBODY receiving the grant, when the claim expires mid-protocol. A store fault after the removal
    /// costs the grant the same way, and raises rather than answering.
    /// <para>
    /// Two callers both receiving it needs a SECOND NODE. Within one process the read and the removal
    /// happen under one hold of the per-key gate, so a redeemer is never between them while another
    /// completes a take - which is what the write-back at that key would have to interleave with. Across
    /// processes the gate holds nothing and the window reopens: the value is read before the claim is
    /// taken, the second caller is handed what it read rather than what it removed, and the reuse check
    /// sees no issued tokens. That is issue 435, and it needs a store primitive this interface does not
    /// expose.
    /// </para>
    /// </para>
    /// </summary>
    /// <param name="authorizationCode">The authorization code to remove and claim.</param>
    /// <returns>
    /// The grant when this caller won the claim; an <c>invalid_grant</c> <see cref="OidcError"/>
    /// otherwise. Otherwise is wider than the obvious list - a concurrent request, an earlier
    /// consumption, an expiry, a code never issued - because the claim can also CONSUME the code and
    /// still refuse, when the lock guarding it expires mid-protocol. So a refusal does not prove another
    /// request took it, and looking for one is how that case is missed.
    /// </returns>
    /// <remarks>
    /// A successfully claimed grant whose <c>IssuedTokens</c> is non-empty indicates the code was
    /// already used to issue tokens (a sequential reuse), which the caller treats as a reuse to be
    /// rejected and whose tokens are revoked.
    /// </remarks>
    Task<Result<AuthorizedGrant, OidcError>> RemoveAuthorizationCodeAsync(string authorizationCode);

    /// <summary>
    /// Updates the authorization grant result based on a specific authorization code and expiration time.
    /// This method allows the authorization grant to be updated with new information or tokens as needed.
    /// </summary>
    /// <param name="authorizationCode">The authorization code associated with the grant result to update.</param>
    /// <param name="authorizedGrant">The updated authorization grant result containing the latest
    /// authentication and authorization details.</param>
    /// <param name="authorizationCodeExpiresIn">The duration after which the updated authorization code will expire.</param>
    /// <returns>A task representing the asynchronous operation of updating the authorization grant result.</returns>
    Task UpdateAuthorizationGrantAsync(
        string authorizationCode,
        AuthorizedGrant authorizedGrant,
        TimeSpan authorizationCodeExpiresIn);
}
