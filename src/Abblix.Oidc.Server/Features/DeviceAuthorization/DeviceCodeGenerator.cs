// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Utils;
using Microsoft.Extensions.Options;

using System.Buffers.Text;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Generates high-entropy device codes for the Device Authorization Grant (RFC 8628).
/// The device code is used by clients to poll the token endpoint.
/// </summary>
/// <param name="options">Configuration options containing device code length settings.</param>
public class DeviceCodeGenerator(IOptions<OidcOptions> options) : IDeviceCodeGenerator
{
    /// <inheritdoc />
    public string GenerateDeviceCode()
        => Base64Url.EncodeToString(
            CryptoRandom.GetRandomBytes(
                options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization)).DeviceCodeLength));
}
