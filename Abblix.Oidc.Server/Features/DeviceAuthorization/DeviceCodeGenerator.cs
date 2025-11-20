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

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Utils;
using Microsoft.Extensions.Options;

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
        => HttpServerUtility.UrlTokenEncode(
            CryptoRandom.GetRandomBytes(
                options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization)).DeviceCodeLength));
}
