// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;

/// <summary>
/// Defines the contract for generating device codes used in the Device Authorization Grant (RFC 8628).
/// </summary>
public interface IDeviceCodeGenerator
{
    /// <summary>
    /// Generates a high-entropy device code that the client uses to poll the token endpoint.
    /// </summary>
    /// <returns>A cryptographically secure, URL-safe device code.</returns>
    string GenerateDeviceCode();
}
