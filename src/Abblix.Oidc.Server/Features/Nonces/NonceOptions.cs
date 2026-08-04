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

using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.Nonces;

/// <summary>
/// Base configuration class for the generic stateless-nonce service.
/// Each feature that needs server-issued, time-bounded opaque tokens
/// (DPoP-Nonce per RFC 9449 §8 / §9 is the current consumer; future
/// candidates include state-parameter validation and challenge-response
/// patterns) defines its own subclass - see <see cref="DPoPNonceOptions"/> -
/// and adds its own slot under <see cref="OidcOptions"/>. This base governs
/// only the primitive's own concerns: issuance window and secret-rotation
/// cadence. Feature-specific policy (e.g. which DPoP endpoints require a
/// nonce) lives on the corresponding subclass.
/// </summary>
/// <remarks>
/// The nonce service is stateless: nonces themselves are not stored. Only a
/// short-lived rotating HMAC secret lives in <c>IDistributedCache</c>, keyed
/// by time bucket so multiple server instances can validate each other's
/// nonces without coordination. Per RFC 9449 §11.3 a nonce mismatch is
/// recoverable - the client receives a fresh nonce and retries - so the
/// brief window during secret rotation where two instances disagree on the
/// current secret degrades to a single client-side retry, not a hard failure.
/// </remarks>
public class NonceOptions
{
    /// <summary>
    /// Maximum age of a server-issued nonce that the validator will still
    /// accept, measured against the timestamp embedded in the nonce. Defaults
    /// to 5 minutes - long enough to survive normal client clock skew and a
    /// retry round-trip, short enough that a leaked nonce stops being useful
    /// quickly.
    /// </summary>
    public TimeSpan AcceptanceWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How often the HMAC secret used to sign nonces is rotated. Each rotation
    /// boundary becomes a new cache bucket; <see cref="AcceptanceWindow"/>
    /// MUST be larger than this so an in-flight nonce signed under the
    /// previous bucket's secret is still verifiable. Defaults to 2 minutes.
    /// </summary>
    public TimeSpan RotationInterval { get; set; } = TimeSpan.FromMinutes(2);
}
