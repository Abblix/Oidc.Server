// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Nonces;

/// <summary>
/// Issues and validates server-issued opaque, time-bounded nonces. The current
/// consumer is DPoP-Nonce per RFC 9449 section 8 / section 9 - the server returns a nonce
/// via the <c>DPoP-Nonce</c> response header and the client echoes it back in
/// the <c>nonce</c> claim of a subsequent DPoP proof to prove freshness - but
/// the primitive is intentionally generic: any future feature needing
/// challenge-response freshness checks can resolve the same service.
/// </summary>
/// <remarks>
/// The default implementation is stateless modulo a short-lived rotating HMAC
/// secret stored in <c>IDistributedCache</c>. No per-nonce state is kept, so
/// <see cref="ValidateAsync"/> does not enforce single-use; replay protection
/// at the proof level is handled separately by the <c>jti</c> replay cache.
/// </remarks>
public interface INonceService
{
    /// <summary>
    /// Mints a fresh nonce string suitable for the <c>DPoP-Nonce</c> response
    /// header. The returned value is opaque to callers - clients must echo it
    /// verbatim.
    /// </summary>
    Task<string> IssueAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies that <paramref name="nonce"/> was issued by this deployment
    /// and is still within the acceptance window.
    /// </summary>
    /// <param name="nonce">The nonce string echoed by the client in its DPoP
    /// proof <c>nonce</c> claim.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><c>null</c> when the nonce is acceptable, otherwise a
    /// <see cref="NonceValidationFailure"/> describing why it is not.</returns>
    Task<NonceValidationFailure?> ValidateAsync(string nonce, CancellationToken cancellationToken = default);
}
