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

namespace Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;

/// <summary>
/// Canonicalizes a user-entered user code before it is matched against a stored code in the
/// Device Authorization Grant (RFC 8628). RFC 8628 Section 6.1 recommends that the server strip
/// readability punctuation the user may have copied (dashes, spaces), case-fold input for
/// single-case character sets, and drop any characters outside the configured alphabet, so that
/// equivalent user input is not rejected as invalid.
/// </summary>
public interface IUserCodeNormalizer
{
    /// <summary>
    /// Produces the canonical form of a user code for comparison: characters outside the
    /// configured alphabet are removed, and case is folded when the alphabet is single-case.
    /// </summary>
    /// <param name="userCode">The raw user code as entered by the end-user.</param>
    /// <returns>The canonical user code used for storage lookup and rate limiting.</returns>
    string Normalize(string userCode);
}
