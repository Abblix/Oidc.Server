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

namespace Abblix.SecurityEvents.Abstractions;

/// <summary>
/// Turns a built SET into its signed compact serialization: the bridge between this package's
/// token model and whatever cryptography the host runs.
/// </summary>
/// <remarks>
/// The signer owns everything the model deliberately does not: which key signs, which algorithm
/// the "alg" header declares, whether a JWE layer wraps the result. RFC 8417 Section 5.1 sets the
/// bar an implementation must meet: unless the token's integrity is ensured by other means, "it
/// MUST be signed using JWS by an issuer that is trusted to do so for the use case". The default
/// implementation binds to the Abblix JWT core; a host with keys behind a boundary this process
/// cannot cross - an HSM, a key vault - substitutes its own.
/// </remarks>
public interface ISecurityEventTokenSigner
{
    /// <summary>
    /// Signs the SET and returns its compact serialization.
    /// </summary>
    /// <param name="token">The SET to sign.</param>
    /// <param name="cancellationToken">Cancels key retrieval or remote signing mid-flight.</param>
    /// <returns>The compact JWS (or JWE-wrapped JWS) representation of the SET.</returns>
    Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default);
}
