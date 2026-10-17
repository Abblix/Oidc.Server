// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils.UnitTests;

using Xunit;

/// <summary>
/// A fingerprint lets records about one credential be told to belong together without the credential being readable
/// in any of them.
/// </summary>
public class FingerprintTests
{
    private const string UserCode = "BCDFGHJK";

    [Fact]
    public void TheSameValue_HasTheSameFingerprint()
        => Assert.Equal(Fingerprint.Of(UserCode).ToString(), Fingerprint.Of(UserCode).ToString());

    [Fact]
    public void DifferentValues_HaveDifferentFingerprints()
        => Assert.NotEqual(Fingerprint.Of(UserCode).ToString(), Fingerprint.Of("BCDFGHJL").ToString());

    [Fact]
    public void TheFingerprint_DoesNotCarryTheValue()
    {
        var fingerprint = Fingerprint.Of(UserCode).ToString();

        Assert.DoesNotContain(UserCode, fingerprint, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(UserCode)))[..fingerprint.Length], fingerprint);
    }

    [Fact]
    public void AnAbsentValue_IsWrittenAsTheLoggingLibraryWritesNull()
        => Assert.Equal(Sanitized.NullText, Fingerprint.Of(null).ToString());
}
