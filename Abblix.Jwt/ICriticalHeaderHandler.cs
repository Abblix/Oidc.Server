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

namespace Abblix.Jwt;

/// <summary>
/// Declares that the host implementation understands a specific JOSE header parameter listed in
/// a JWS 'crit' header (RFC 7515 §4.1.11).
/// </summary>
/// <remarks>
/// RFC 7515 §4.1.11 requires verifiers to reject any JWS whose 'crit' header lists a parameter
/// the verifier does not understand. Hosts implementing JOSE extensions that travel through the
/// 'crit' contract (for example RFC 7797 'b64', or DPoP-related parameters) register an
/// <see cref="ICriticalHeaderHandler"/> for each supported extension name; the validator rejects
/// any JWS whose 'crit' lists a name not declared by some registered handler.
/// </remarks>
public interface ICriticalHeaderHandler
{
    /// <summary>
    /// The JOSE header parameter name this handler declares understanding of.
    /// MUST match the literal string used in the 'crit' array (case-sensitive, byte-exact).
    /// </summary>
    string HeaderName { get; }
}
