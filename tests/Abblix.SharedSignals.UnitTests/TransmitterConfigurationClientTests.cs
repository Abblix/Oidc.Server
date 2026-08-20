// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using System.Net.Mime;
using Abblix.SharedSignals.Receiver;
using Abblix.SharedSignals.Receiver.SecurityEvent;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the discovery client's contract (SSF 1.0 Sections 7.2, 7.2.1): the document comes from
/// the insertion-derived well-known address, and it is accepted only when it asserts the issuer
/// it was fetched for.
/// </summary>
public class TransmitterConfigurationClientTests
{
    [Fact]
    public async Task Get_FetchesTheWellKnownAddress_AndReturnsTheMetadata()
    {
        var handler = new StubHttpHandler().Enqueue(
            HttpStatusCode.OK,
            """
            {
                "issuer": "https://tr.example.com/issuer1",
                "jwks_uri": "https://tr.example.com/issuer1/jwks.json"
            }
            """);
        var client = new TransmitterConfigurationClient(handler.CreateClient());

        var metadata = await client.GetAsync(
            new Uri("https://tr.example.com/issuer1"), TestContext.Current.CancellationToken);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(
            new Uri("https://tr.example.com/.well-known/ssf-configuration/issuer1"),
            request.Address);
        Assert.Equal("https://tr.example.com/issuer1", metadata.Issuer);
    }

    [Fact]
    public async Task GetFromExplicitAddress_FetchesThatAddress_AndStillReturnsTheMetadata()
    {
        // The overload for transmitters publishing the document off the well-known path: the
        // address changes, nothing else does.
        var handler = new StubHttpHandler().Enqueue(
            HttpStatusCode.OK,
            """
            {
                "issuer": "https://tr.example.com/issuer1",
                "jwks_uri": "https://tr.example.com/issuer1/jwks.json"
            }
            """);
        var client = new TransmitterConfigurationClient(handler.CreateClient());

        var metadata = await client.GetAsync(
            new Uri("https://tr.example.com/issuer1"),
            new Uri("https://tr.example.com/internal/ssf-config"),
            TestContext.Current.CancellationToken);

        Assert.Equal(
            new Uri("https://tr.example.com/internal/ssf-config"),
            Assert.Single(handler.Requests).Address);
        Assert.Equal("https://tr.example.com/issuer1", metadata.Issuer);
    }

    [Fact]
    public async Task GetFromExplicitAddress_DocumentAssertingAnotherIssuer_IsStillRefused()
    {
        // The address says where the bytes come from, never who they speak for: the issuer
        // identity check binds this overload exactly as it binds the well-known one.
        var handler = new StubHttpHandler().Enqueue(
            HttpStatusCode.OK, """{"issuer": "https://tr.example.com/issuer2"}""");
        var client = new TransmitterConfigurationClient(handler.CreateClient());

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await client.GetAsync(
                new Uri("https://tr.example.com/issuer1"),
                new Uri("https://tr.example.com/internal/ssf-config"),
                TestContext.Current.CancellationToken));

        Assert.Contains("issuer2", exception.Message);
    }

    [Fact]
    public async Task Get_DocumentAssertingAnotherIssuer_IsRefused()
    {
        // Without the identity check, a document served on one issuer's well-known path could
        // bind the receiver to another issuer of the same host.
        var handler = new StubHttpHandler().Enqueue(
            HttpStatusCode.OK, """{"issuer": "https://tr.example.com/issuer2"}""");
        var client = new TransmitterConfigurationClient(handler.CreateClient());

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await client.GetAsync(
                new Uri("https://tr.example.com/issuer1"), TestContext.Current.CancellationToken));

        Assert.Contains("issuer2", exception.Message);
    }

    [Fact]
    public async Task Get_RootIssuer_ToleratesTheNormalizedTrailingSlash()
    {
        // Uri normalizes a root issuer to a "/" path, so "https://tr.example.com" and its
        // slash-terminated spelling are one identity; distinct paths stay distinct.
        var handler = new StubHttpHandler().Enqueue(
            HttpStatusCode.OK, """{"issuer": "https://tr.example.com/"}""");
        var client = new TransmitterConfigurationClient(handler.CreateClient());

        var metadata = await client.GetAsync(
            new Uri("https://tr.example.com"), TestContext.Current.CancellationToken);

        Assert.Equal("https://tr.example.com/", metadata.Issuer);
    }

    [Fact]
    public async Task Get_ErrorStatus_SurfacesAsHttpRequestException()
    {
        var handler = new StubHttpHandler().Enqueue(HttpStatusCode.NotFound);
        var client = new TransmitterConfigurationClient(handler.CreateClient());

        await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await client.GetAsync(
                new Uri("https://tr.example.com"), TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("https://evil@tr.example.com")]
    [InlineData("https://tr.example.com#fragment")]
    public async Task Get_IssuerDifferingOnlyInUserInfoOrFragment_IsStillRefused(string declared)
    {
        // Uri.Equals disregards exactly these two components, so a naive Uri comparison would
        // confirm the identity of a document asserting a DIFFERENT issuer string; the check
        // compares normalized absolute URIs, where every component counts.
        var handler = new StubHttpHandler().Enqueue(
            HttpStatusCode.OK, $$"""{"issuer": "{{declared}}"}""");
        var client = new TransmitterConfigurationClient(handler.CreateClient());

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await client.GetAsync(
                new Uri("https://tr.example.com"), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Get_NonJsonContentType_IsRefused()
    {
        // "that document MUST be returned using the 'application/json' content type"
        // (SSF 1.0 Section 7.2) - and the deserializer itself parses whatever it is handed, so
        // the check must be the client's own.
        var handler = new StubHttpHandler().Enqueue(
            HttpStatusCode.OK, """{"issuer": "https://tr.example.com"}""", MediaTypeNames.Text.Html);
        var client = new TransmitterConfigurationClient(handler.CreateClient());

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await client.GetAsync(
                new Uri("https://tr.example.com"), TestContext.Current.CancellationToken));

        Assert.Contains(MediaTypeNames.Text.Html, exception.Message);
    }
}
