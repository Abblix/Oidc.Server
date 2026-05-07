// Abblix OIDC Server Library
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

using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// Validates a DPoP proof JWT per RFC 9449 §4.2 / §4.3 (structure, signature, claim
/// shape) but excluding replay-cache and nonce checks. Those layered checks land
/// alongside the <c>jti</c>-replay-cache and DPoP-Nonce service in a separate slice and
/// build on the <see cref="Proof"/> returned by a successful validation here.
/// </summary>
public interface IProofValidator
{
    /// <summary>
    /// Validates <paramref name="proofJwt"/> as a DPoP proof for the request identified by
    /// <paramref name="httpMethod"/> and <paramref name="requestUri"/>. When
    /// <paramref name="accessToken"/> is supplied (the proof accompanies a bearer-style
    /// access-token presentation), the proof's <c>ath</c> claim is verified against the
    /// access-token hash per RFC 9449 §4.2.
    /// </summary>
    /// <param name="proofJwt">The compact JWS form of the DPoP proof, taken from the
    /// <c>DPoP</c> request header.</param>
    /// <param name="httpMethod">The HTTP method of the current request, in upper case
    /// (e.g. <c>POST</c>, <c>GET</c>).</param>
    /// <param name="requestUri">The HTTP target URI of the current request.</param>
    /// <param name="accessToken">The access token presented alongside the proof, when the
    /// proof secures a resource-server request. <c>null</c> at the token endpoint where no
    /// access token is yet bound.</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous call.</param>
    /// <returns>A <see cref="Result{Proof, ProofError}"/>: <see cref="Proof"/> when every
    /// validation step passes, otherwise <see cref="ProofError"/> describing the failure
    /// reason.</returns>
    Task<Result<Proof, ProofError>> ValidateAsync(
        string proofJwt,
        string httpMethod,
        Uri requestUri,
        string? accessToken = null,
        CancellationToken cancellationToken = default);
}
