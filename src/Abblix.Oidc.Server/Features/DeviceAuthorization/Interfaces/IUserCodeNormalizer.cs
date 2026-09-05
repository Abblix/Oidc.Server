// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
