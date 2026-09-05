// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;

/// <summary>
/// Defines the contract for generating user codes used in the Device Authorization Grant (RFC 8628).
/// </summary>
public interface IUserCodeGenerator
{
    /// <summary>
    /// Generates a user-friendly numeric code that the end-user enters on the verification page.
    /// </summary>
    /// <returns>A numeric verification code (e.g., "1234-5678").</returns>
    string GenerateUserCode();
}
