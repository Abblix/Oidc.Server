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
