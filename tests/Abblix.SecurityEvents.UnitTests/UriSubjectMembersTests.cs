// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.SecurityEvents.Subjects;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// The members RFC 9493 defines as URIs - the account's "acct" URI, the DID URL and the URI format's value - are read
/// as absolute URIs, written back as they were spelled, and refused when they are not URIs at all.
/// </summary>
public class UriSubjectMembersTests
{
    /// <summary>
    /// DIDs of several methods, with the characters their method-specific identifiers use, and a DID URL with a path,
    /// a query and a fragment: each reads as a URI and is written back unchanged.
    /// </summary>
    [Theory]
    [InlineData("did:example:123456")]
    [InlineData("did:web:example.com%3A8443:users:alice")]
    [InlineData("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")]
    [InlineData("did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w:eyJkZWx0YSI6eyJwYXRjaGVzIjpbXX19")]
    [InlineData("did:example:123456/did/url/path?versionId=1#keys-1")]
    public void ADidUrl_RoundTripsAsWritten(string url)
    {
        var json = $$"""{"format":"did","url":"{{url}}"}""";

        var subject = Assert.IsType<DidSubject>(JsonSerializer.Deserialize<SubjectIdentifier>(json));

        Assert.True(subject.Url.IsAbsoluteUri);
        Assert.Equal(url, JsonSerializer.SerializeToNode<SubjectIdentifier>(subject)![SubjectMemberNames.Url]!.GetValue<string>());
    }

    /// <summary>
    /// A value that is not an absolute URI does not meet the format the member belongs to, and the document is
    /// refused (RFC 9493 Section 3: every member "MUST match the rules specified for that member").
    /// </summary>
    [Theory]
    [InlineData("""{"format":"uri","uri":"not a uri"}""")]
    [InlineData("""{"format":"uri","uri":"/relative/path"}""")]
    [InlineData("""{"format":"account","uri":"example.user@service.example.com"}""")]
    [InlineData("""{"format":"did","url":"123456"}""")]
    public void AValueThatIsNoUri_IsRefused(string json)
        => Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<SubjectIdentifier>(json));

    /// <summary>
    /// Two spellings of one URI stay two identifiers: the value is written back as it was read.
    /// </summary>
    [Fact]
    public void AUri_KeepsItsSpelling()
    {
        const string spelled = "HTTPS://User.Example.COM:443/Path";
        var subject = new UriSubject(new Uri(spelled));

        var written = JsonSerializer.SerializeToNode<SubjectIdentifier>(subject)!.AsObject();

        Assert.Equal(spelled, written[SubjectMemberNames.Uri]!.GetValue<string>());
    }
}
