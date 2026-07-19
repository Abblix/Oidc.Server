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

using System.Text;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Canonicalizes user-entered user codes for the Device Authorization Grant (RFC 8628) following
/// the input-processing guidance in Section 6.1: punctuation added for readability (dashes,
/// spaces) and any other characters outside the configured alphabet are dropped, and case is
/// folded when the alphabet is single-case so that a user typing the equivalent lowercase (or
/// uppercase) form is not rejected.
/// </summary>
/// <param name="options">Configuration options carrying the user code alphabet.</param>
public class UserCodeNormalizer(IOptions<OidcOptions> options) : IUserCodeNormalizer
{
    /// <inheritdoc />
    public string Normalize(string userCode)
    {
        var alphabet = options.Value.DeviceAuthorization
            .NotNull(nameof(OidcOptions.DeviceAuthorization))
            .UserCodeAlphabet;

        // Case-fold only when the alphabet is unambiguously single-case: folding a mixed-case
        // alphabet would collapse distinct code points, and folding a caseless (e.g. numeric)
        // alphabet is a no-op anyway.
        var hasUpper = alphabet.Any(char.IsUpper);
        var hasLower = alphabet.Any(char.IsLower);
        var fold = (hasUpper, hasLower) switch
        {
            (true, false) => (Func<char, char>)char.ToUpperInvariant,
            (false, true) => char.ToLowerInvariant,
            _ => static c => c,
        };

        var allowed = alphabet.ToHashSet();
        var builder = new StringBuilder(userCode.Length);
        foreach (var character in userCode)
        {
            var folded = fold(character);
            if (allowed.Contains(folded))
                builder.Append(folded);
        }

        return builder.ToString();
    }
}
