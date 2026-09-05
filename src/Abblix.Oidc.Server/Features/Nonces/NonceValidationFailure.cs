// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Nonces;

/// <summary>
/// Reasons a server-issued nonce can fail validation. The categories are for
/// log filters and metrics - at the protocol layer DPoP-Nonce flows surface
/// every failure as the same RFC 9449 §8 <c>use_dpop_nonce</c> error with a
/// freshly issued nonce in the response header, regardless of the underlying
/// reason.
/// </summary>
public enum NonceValidationFailure
{
    /// <summary>
    /// The nonce string could not be Base64Url-decoded or has the wrong byte
    /// length to be one of ours. Often a sign of a client mis-handling the
    /// <c>DPoP-Nonce</c> header (truncation, extra whitespace) or of an
    /// attacker probing the endpoint.
    /// </summary>
    Malformed,

    /// <summary>
    /// The nonce decoded cleanly but its embedded timestamp is outside the
    /// configured acceptance window - either older than
    /// <c>AcceptanceWindow</c> or too far in the future relative to server
    /// clock. Routine for clients that cached a nonce too long.
    /// </summary>
    OutOfWindow,

    /// <summary>
    /// The HMAC tag does not match what the server would compute for the
    /// embedded timestamp under any in-rotation secret. Indicates either
    /// tampering, a nonce minted by a different deployment, or a brief
    /// rotation race window where the issuing instance's secret has not yet
    /// propagated through <c>IDistributedCache</c>.
    /// </summary>
    BadSignature,
}
