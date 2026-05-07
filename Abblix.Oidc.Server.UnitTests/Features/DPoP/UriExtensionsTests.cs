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

using System;

using Abblix.Oidc.Server.Features.DPoP;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DPoP;

/// <summary>
/// Tests for <see cref="UriExtensions.Normalize"/> covering the canonical-string form
/// used for DPoP <c>htu</c> comparison per RFC 9449 §6 and RFC 3986 §6.2: scheme and
/// host lowercased, default ports stripped, query and fragment dropped, path preserved.
/// </summary>
public class UriExtensionsTests
{
    [Theory]
    // Basic identity: already-canonical URI passes through unchanged.
    [InlineData("https://example.com/path", "https://example.com/path")]

    // Case normalisation per RFC 3986 §6.2.2.1 — scheme and host folded to lowercase,
    // path case is significant and stays verbatim.
    [InlineData("HTTPS://Example.COM/Path", "https://example.com/Path")]

    // Default-port stripping per RFC 3986 §6.2.3.
    [InlineData("https://example.com:443/path", "https://example.com/path")]
    [InlineData("http://example.com:80/path", "http://example.com/path")]

    // Non-default port preserved.
    [InlineData("https://example.com:8443/path", "https://example.com:8443/path")]

    // Query and fragment dropped (DPoP-specific, RFC 9449 §4.3 / §6).
    [InlineData("https://example.com/path?q=1", "https://example.com/path")]
    [InlineData("https://example.com/path#frag", "https://example.com/path")]
    [InlineData("https://example.com/path?q=1#frag", "https://example.com/path")]

    // Empty path becomes "/" per RFC 3986 §6.2.3.
    [InlineData("https://example.com", "https://example.com/")]

    // Trailing slash is significant (different resource) and is preserved.
    [InlineData("https://example.com/foo/", "https://example.com/foo/")]

    // Percent-encoding case normalisation per RFC 3986 §6.2.2.2: hex digits
    // are uppercased; the literal characters they represent are not decoded.
    [InlineData("https://example.com/foo%2fbar", "https://example.com/foo%2Fbar")]
    public void Normalize_ProducesCanonicalHtuForm(string input, string expected)
    {
        Assert.Equal(expected, new Uri(input).Normalize());
    }

}
