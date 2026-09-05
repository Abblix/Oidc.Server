// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Generates user codes for the Device Authorization Grant (RFC 8628).
/// The alphabet used for code generation is configurable to support
/// numeric, alphabetic, or alphanumeric codes.
/// </summary>
/// <param name="options">Configuration options containing user code settings.</param>
public class UserCodeGenerator(IOptions<OidcOptions> options) : IUserCodeGenerator
{
    /// <inheritdoc />
    public string GenerateUserCode()
    {
        var deviceAuthOptions = options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization));
        var length = deviceAuthOptions.UserCodeLength;
        var alphabet = deviceAuthOptions.UserCodeAlphabet;

        var chars = new char[length];

        for (var i = 0; i < length; i++)
        {
            // Use GetInt32 for uniform distribution without modulo bias
            // RFC 8628 Section 6.1 recommends restricting the character set so the code is quick to
            // type on a phone; it states no requirement, so the fixed alphabet is this server's choice.
            // The uniform draw is what makes the entropy claim in Section 5.1 true of it.
            chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        }

        return new string(chars);
    }
}
