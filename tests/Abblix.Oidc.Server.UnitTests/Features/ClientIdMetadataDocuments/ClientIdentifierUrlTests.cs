// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// Which client identifiers are Client Identifier URLs the server fetches (draft-ietf-oauth-client-id-metadata-document
/// section 3), read as the string the client sent.
/// </summary>
public class ClientIdentifierUrlTests
{
    [Theory]
    [InlineData("https://client.example.com/metadata.json")]
    [InlineData("https://client.example.com:8443/metadata.json")]
    [InlineData("https://client.example.com/a/b")]
    [InlineData("https://client.example.com/~user/client")]
    [InlineData("https://[2001:4860:4860::8888]/client")]
    public void AUrlWithinTheRules_IsFetchedFromItself(string clientId)
    {
        Assert.Null(ClientIdentifierUrl.WhyNotFetched(clientId, out var url));
        Assert.Equal(clientId, url!.AbsoluteUri);
    }

    [Theory]
    // "MUST use the https URL scheme", compared as written
    [InlineData("http://client.example.com/metadata.json")]
    [InlineData("HTTPS://client.example.com/metadata.json")]
    [InlineData("client-1")]
    // "MUST NOT contain a userinfo component"
    [InlineData("https://user@client.example.com/metadata.json")]
    [InlineData("https://user:password@client.example.com/metadata.json")]
    // "MUST contain a path component other than /"
    [InlineData("https://client.example.com")]
    [InlineData("https://client.example.com/")]
    // "MUST NOT contain single-dot or double-dot path components", percent-encoded ones included
    [InlineData("https://client.example.com/a/../metadata.json")]
    [InlineData("https://client.example.com/./metadata.json")]
    [InlineData("https://client.example.com/a/%2e%2e/metadata.json")]
    // An encoded slash or backslash, or a segment starting with two dots, which a server behind the URL may read as a
    // step out of the path an allow-list names
    [InlineData("https://client.example.com/clients/..%2Fother/metadata.json")]
    [InlineData("https://client.example.com/clients%2F..%2Fother")]
    [InlineData("https://client.example.com/clients%2f..%2fother")]
    [InlineData("https://client.example.com/clients%5C..%5Cother")]
    [InlineData("https://client.example.com/clients/..other/metadata.json")]
    // "SHOULD NOT contain a query component", refused as this server's choice
    [InlineData("https://client.example.com/metadata.json?tenant=a")]
    // "MUST NOT contain a fragment component"
    [InlineData("https://client.example.com/metadata.json#x")]
    // Written in another form than the one the request would reach, so the document could never name it
    [InlineData("https://client.example.com:443/metadata.json")]
    [InlineData("https://Client.Example.com/metadata.json")]
    [InlineData("https://client.example.com/%7Euser")]
    [InlineData("https://client.example.com/a b")]
    public void AUrlBreakingARule_IsNotFetched(string clientId)
    {
        Assert.NotNull(ClientIdentifierUrl.WhyNotFetched(clientId, out var url));
        Assert.Null(url);
    }

    [Theory]
    [InlineData("https://apps.example.com/client", true)]
    [InlineData("https://apps.example.com/a/b/client", true)]
    [InlineData("https://example.com/clients/x", true)]
    [InlineData("https://example.com/other/x", false)]
    [InlineData("https://apps.example.com.attacker.test/client", false)]
    [InlineData("https://apps.example.com:8443/client", false)]
    public void AnAllowList_AdmitsOnlyTheUrlsItsPrefixesBegin(string clientId, bool allowed)
        => Assert.Equal(
            allowed,
            ClientIdentifierUrl.IsAllowed(clientId, ["https://apps.example.com/", "https://example.com/clients/"]));

    [Fact]
    public void NoAllowList_AdmitsEveryUrl()
        => Assert.True(ClientIdentifierUrl.IsAllowed("https://anything.example/client", null));
}
