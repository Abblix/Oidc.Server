// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
