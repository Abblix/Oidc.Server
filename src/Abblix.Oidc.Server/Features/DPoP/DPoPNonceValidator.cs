// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.Nonces;

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// Base class for DPoP-aware endpoint validators that enforce the RFC 9449 §8 nonce
/// challenge-response loop. Encapsulates the proof-claim check, fresh-nonce issuance,
/// and <see cref="UseDPoPNonceError"/> shaping; concrete validators override
/// <see cref="LogNonceChallengeIssued"/> to attribute the «challenge issued» event to
/// their own endpoint <c>EventId</c>.
/// </summary>
public abstract class DPoPNonceValidator(INonceService nonceService)
{
    /// <summary>
    /// Enforces the nonce policy on <paramref name="proof"/>. Returns <c>null</c> when
    /// the proof carries an acceptable nonce; otherwise mints a fresh nonce, fires
    /// <see cref="LogNonceChallengeIssued"/> for endpoint-specific logging, and returns
    /// a <see cref="UseDPoPNonceError"/> the response formatter attaches to the
    /// <c>DPoP-Nonce</c> response header.
    /// </summary>
    protected async Task<OidcError?> EnforceNonceAsync(Proof proof)
    {
        var nonceClaim = proof.Token.Payload.Nonce;
        if (nonceClaim is null)
            return await UseDPoPNonce();

        var failure = await nonceService.ValidateAsync(nonceClaim);
        if (failure is not null)
            return await UseDPoPNonce();

        return null;
    }

    private async Task<UseDPoPNonceError> UseDPoPNonce()
    {
        var nonce = await nonceService.IssueAsync();
        LogNonceChallengeIssued();
        return new UseDPoPNonceError(nonce);
    }

    /// <summary>
    /// Emits a per-endpoint log entry when a DPoP-Nonce challenge is issued. Each
    /// derived validator implements via a <c>[LoggerMessage]</c>-decorated partial
    /// method so its own <c>EventId</c> identifies the originating endpoint.
    /// </summary>
    protected abstract void LogNonceChallengeIssued();
}
