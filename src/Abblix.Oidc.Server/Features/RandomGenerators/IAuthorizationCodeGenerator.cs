// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Defines a contract for generating unique authorization codes for use in OAuth 2.0 authorization code flows.
/// Implementations of this interface should ensure that the generated codes are cryptographically secure
/// and suitable for one-time use in authenticating and authorizing access.
/// </summary>
public interface IAuthorizationCodeGenerator
{
    /// <summary>
    /// Generates a unique, cryptographically secure authorization code.
    /// </summary>
    /// <returns>A string representing a unique authorization code.</returns>
    string GenerateAuthorizationCode();
}
