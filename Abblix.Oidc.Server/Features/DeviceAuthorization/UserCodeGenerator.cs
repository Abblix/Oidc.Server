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
            // RFC 8628 Section 6.1: User codes MUST contain only characters from a predefined character set
            // with uniform random distribution for security
            chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        }

        return new string(chars);
    }
}
