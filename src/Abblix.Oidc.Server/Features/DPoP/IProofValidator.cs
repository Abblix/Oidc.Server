// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// Validates a DPoP proof JWT per RFC 9449 section 4.2 / section 4.3 (structure, signature, claim
/// shape) but excluding replay-cache and nonce checks. Those layered checks land
/// alongside the <c>jti</c>-replay-cache and DPoP-Nonce service in a separate slice and
/// build on the <see cref="Proof"/> returned by a successful validation here.
/// </summary>
public interface IProofValidator
{
    /// <summary>
    /// Validates <paramref name="proofJwt"/> as a DPoP proof for the current request.
    /// The HTTP method and URI used for <c>htm</c> / <c>htu</c> binding checks come from
    /// <see cref="Abblix.Oidc.Server.Common.Interfaces.IRequestInfoProvider"/> injected
    /// into the validator, so callers never need to thread them through. When
    /// <paramref name="accessToken"/> is supplied (the proof accompanies a bearer-style
    /// access-token presentation), the proof's <c>ath</c> claim is verified against the
    /// access-token hash per RFC 9449 section 4.2.
    /// </summary>
    /// <param name="proofJwt">The compact JWS form of the DPoP proof, taken from the
    /// <c>DPoP</c> request header.</param>
    /// <param name="accessToken">The access token presented alongside the proof, when the
    /// proof secures a resource-server request. <c>null</c> at the token endpoint where no
    /// access token is yet bound.</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous call.</param>
    /// <returns>A <see cref="Result{Proof, ProofError}"/>: <see cref="Proof"/> when every
    /// validation step passes, otherwise <see cref="ProofError"/> describing the failure
    /// reason.</returns>
    Task<Result<Proof, ProofError>> ValidateAsync(
        string proofJwt,
        string? accessToken = null,
        CancellationToken cancellationToken = default);
}
