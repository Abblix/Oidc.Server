// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DeviceAuthorization;

/// <summary>
/// Verifies user code canonicalization per the input-processing guidance in RFC 8628 Section 6.1:
/// readability punctuation and out-of-alphabet characters are stripped, and case is folded only
/// when the configured alphabet is single-case.
/// </summary>
public class UserCodeNormalizerTests
{
    private const string Consonants = "BCDFGHJKLMNPQRSTVWXZ";
    private const string Digits = "0123456789";

    [Theory]
    // Consonant (upper-only) alphabet: lowercase folds up, dashes and spaces are dropped.
    [InlineData(Consonants, "wdjb-mjht", "WDJBMJHT")]
    [InlineData(Consonants, "WDJB-MJHT", "WDJBMJHT")]
    [InlineData(Consonants, " wdjb mjht ", "WDJBMJHT")]
    // Numeric alphabet is caseless: only dashes/spaces are dropped, digits preserved.
    [InlineData(Digits, "019-450-730", "019450730")]
    [InlineData(Digits, "019 450 730", "019450730")]
    public void Normalize_StripsPunctuationAndFoldsCaseForSingleCaseAlphabets(
        string alphabet, string input, string expected)
    {
        var normalizer = CreateNormalizer(alphabet);

        Assert.Equal(expected, normalizer.Normalize(input));
    }

    [Fact]
    public void Normalize_DoesNotFoldCase_ForMixedCaseAlphabet()
    {
        // A mixed-case alphabet distinguishes 'a' from 'A'; folding would collapse them, so the
        // normalizer must preserve case and only drop characters outside the set.
        var normalizer = CreateNormalizer("aB");

        // 'a' and 'B' are in the set and kept; the dash is dropped.
        Assert.Equal("aB", normalizer.Normalize("a-B"));
        // 'A' and 'b' are NOT in the set (no case folding) and are dropped; 'a' survives.
        Assert.Equal("a", normalizer.Normalize("A-a-b"));
    }

    private static UserCodeNormalizer CreateNormalizer(string alphabet) => new(
        Options.Create(new OidcOptions
        {
            DeviceAuthorization = new DeviceAuthorizationOptions
            {
                CodeLifetime = TimeSpan.FromMinutes(5),
                PollingInterval = TimeSpan.FromSeconds(5),
                DeviceCodeLength = 32,
                UserCodeLength = 8,
                VerificationUri = new Uri("https://auth.example.com/device"),
                UserCodeAlphabet = alphabet,
            },
        }));
}
