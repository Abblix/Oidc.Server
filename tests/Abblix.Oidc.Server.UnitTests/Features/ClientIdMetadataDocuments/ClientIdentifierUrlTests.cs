// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Utils;
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
        Assert.Null(ClientIdentifierUrl.WhyNotFetched(clientId, OutboundAddressRule.NoSpecialPurpose, out var url));
        Assert.Equal(clientId, url!.AbsoluteUri);
        Assert.True(ClientIdentifierUrl.IsWithheldFromRegistration(clientId));
    }

    /// <summary>
    /// Registration withholds every spelling of an https URL, not only the one a document is fetched under, so no
    /// registration holds an id reading as a document's URL.
    /// </summary>
    [Theory]
    [InlineData("HTTPS://client.example.com/metadata.json")]
    [InlineData("Https://client.example.com/metadata.json")]
    [InlineData("hTtPs://client.example.com/metadata.json")]
    [InlineData(" https://client.example.com/metadata.json")]
    [InlineData("https://client.example.com/metadata.json ")]
    [InlineData(" HTTPS://client.example.com/metadata.json ")]
    [InlineData("\thttps://client.example.com/metadata.json")]
    [InlineData("https://client.example.com/metadata.json\r\n")]
    [InlineData("https://Client.Example.com:443/metadata.json")]
    [InlineData("https://client.example.com")]
    [InlineData("https://")]
    public void AnHttpsUrlInAnySpelling_IsWithheldFromRegistration(string clientId)
        => Assert.True(ClientIdentifierUrl.IsWithheldFromRegistration(clientId));

    [Theory]
    [InlineData("client-1")]
    [InlineData("ABC")]
    [InlineData("httpsclient")]
    [InlineData("https-client")]
    [InlineData("http://client.example.com/metadata.json")]
    [InlineData("HTTP://client.example.com/metadata.json")]
    [InlineData("urn:example:client")]
    public void AnIdThatIsNoHttpsUrl_MayBeRegistered(string clientId)
        => Assert.False(ClientIdentifierUrl.IsWithheldFromRegistration(clientId));

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
    // Section 10.7 holds the URL to the special-purpose registries as written, NAT64 and 6to4 whatever they carry
    [InlineData("https://[64:ff9b::808:808]/metadata.json")]
    [InlineData("https://[2002:808:808::]/metadata.json")]
    [InlineData("https://[::ffff:0:808:808]/metadata.json")]
    [InlineData("https://192.0.2.1/metadata.json")]
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
        Assert.NotNull(ClientIdentifierUrl.WhyNotFetched(clientId, OutboundAddressRule.NoSpecialPurpose, out var url));
        Assert.Null(url);
    }

    /// <summary>
    /// Section 10.7's exception reaches loopback as written, and nothing else of the special-purpose registries: not a
    /// private network, not link-local, and not a mapped or NAT64 form of a loopback address.
    /// </summary>
    [Theory]
    [InlineData("https://127.0.0.1/metadata.json", OutboundAddressRule.NoSpecialPurposeButLoopback, true)]
    [InlineData("https://127.0.0.2:8443/metadata.json", OutboundAddressRule.NoSpecialPurposeButLoopback, true)]
    [InlineData("https://[::1]:5001/metadata.json", OutboundAddressRule.NoSpecialPurposeButLoopback, true)]
    [InlineData("https://127.0.0.1/metadata.json", OutboundAddressRule.NoSpecialPurpose, false)]
    [InlineData("https://[::1]:5001/metadata.json", OutboundAddressRule.NoSpecialPurpose, false)]
    [InlineData("https://10.0.0.5/metadata.json", OutboundAddressRule.NoSpecialPurposeButLoopback, false)]
    [InlineData("https://192.168.1.5/metadata.json", OutboundAddressRule.NoSpecialPurposeButLoopback, false)]
    [InlineData("https://169.254.169.254/metadata.json", OutboundAddressRule.NoSpecialPurposeButLoopback, false)]
    [InlineData("https://[::ffff:7f00:1]/metadata.json", OutboundAddressRule.NoSpecialPurposeButLoopback, false)]
    [InlineData("https://[64:ff9b::7f00:1]/metadata.json", OutboundAddressRule.NoSpecialPurposeButLoopback, false)]
    public void ALiteralAddress_IsFetchedOnlyWhenItsRuleReachesIt(string clientId, OutboundAddressRule rule, bool fetched)
        => Assert.Equal(fetched, ClientIdentifierUrl.WhyNotFetched(clientId, rule, out _) is null);

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
