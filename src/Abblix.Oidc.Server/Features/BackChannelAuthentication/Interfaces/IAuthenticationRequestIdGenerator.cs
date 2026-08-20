// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

/// <summary>
/// Defines the contract for generating unique authentication request identifiers in the context of a backchannel
/// or other authentication flows. This identifier is used to track and reference individual authentication requests.
/// </summary>
public interface IAuthenticationRequestIdGenerator
{
    /// <summary>
    /// Generates a unique authentication request ID, which is used to identify a specific
    /// authentication request during the backchannel authentication flow or similar processes.
    /// </summary>
    /// <returns>The generated authentication request ID as a string.</returns>
    string GenerateAuthenticationRequestId();
}
