// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Tokens.Revocation;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Stores the moment before which every token issued to a principal is treated as revoked.
/// </summary>
/// <remarks>
/// Kept apart from <see cref="ITokenRegistry"/> because the two answer different questions. That one records
/// the fate of a token that already exists, one entry per token; this one records a fact about a principal,
/// which the token is measured against. A cutoff is therefore one write however many tokens it invalidates,
/// and it needs no cleanup when the user signs in again: the tokens minted afterwards carry a later
/// <c>iat</c> and pass on their own.
/// <para>
/// A boolean would not do. A subject outlives any single sign-in, so a flag saying "revoked" would keep
/// refusing the tokens of every later session too.
/// </para>
/// </remarks>
public interface IRevocationCutoffRegistry
{
    /// <summary>
    /// The cutoff recorded for a principal, or <c>null</c> when none is.
    /// </summary>
    /// <param name="scope">Whether the principal is an end user or a single session.</param>
    /// <param name="principal">The subject identifier or the session identifier.</param>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    /// <returns>The moment before which tokens for this principal are revoked.</returns>
    Task<DateTimeOffset?> GetCutoffAsync(
        RevocationScope scope, string principal, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records a cutoff for a principal.
    /// </summary>
    /// <param name="scope">Whether the principal is an end user or a single session.</param>
    /// <param name="principal">The subject identifier or the session identifier.</param>
    /// <param name="cutoff">The moment before which tokens for this principal are revoked.</param>
    /// <param name="expiresAt">When the record may be dropped, which is when the longest-lived token it
    /// could refuse has expired anyway.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>A task that completes once the cutoff has been written.</returns>
    Task SetCutoffAsync(
        RevocationScope scope,
        string principal,
        DateTimeOffset cutoff,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);
}
