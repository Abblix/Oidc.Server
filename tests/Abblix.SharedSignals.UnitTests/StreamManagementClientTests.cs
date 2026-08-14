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

using System.Net;
using System.Text.Json.Nodes;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Receiver;
using Abblix.SharedSignals.Receiver.SecurityEvent;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the management client's contract per SSF 1.0 Section 8.1: which endpoint each method
/// speaks to, which statuses are answers rather than errors - 409 on create, 202 on updates,
/// 429 on the throttled calls - and the issuer check every configuration read back must pass.
/// </summary>
public class StreamManagementClientTests
{
    private const string Issuer = "https://tr.example.com";

    private static readonly TransmitterConfiguration Transmitter = new()
    {
        Issuer = Issuer,
        ConfigurationEndpoint = new Uri("https://tr.example.com/ssf/stream"),
        StatusEndpoint = new Uri("https://tr.example.com/ssf/status"),
        AddSubjectEndpoint = new Uri("https://tr.example.com/ssf/subjects-add"),
        RemoveSubjectEndpoint = new Uri("https://tr.example.com/ssf/subjects-remove"),
        VerificationEndpoint = new Uri("https://tr.example.com/ssf/verify"),
    };

    /// <summary>
    /// A minimal conformant configuration document asserting the transmitter's issuer.
    /// </summary>
    private const string ConfigurationJson =
        """
        {
            "stream_id": "s-1",
            "iss": "https://tr.example.com",
            "aud": "https://receiver.example.com",
            "events_delivered": [],
            "delivery": {
                "method": "urn:ietf:rfc:8936",
                "endpoint_url": "https://tr.example.com/ssf/poll/s-1"
            }
        }
        """;

    private static StreamManagementClient CreateClient(StubHttpHandler handler)
        => new(handler.CreateClient(), Transmitter);

    [Fact]
    public async Task Create_Created_PostsTheReceiverHalf_AndReturnsTheConfiguration()
    {
        var handler = new StubHttpHandler().Enqueue(HttpStatusCode.Created, ConfigurationJson);

        var created = await CreateClient(handler).CreateAsync(
            new CreateStreamRequest { Description = "Stream for Receiver A" },
            TestContext.Current.CancellationToken);

        Assert.NotNull(created);
        Assert.Equal("s-1", created.StreamId);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(Transmitter.ConfigurationEndpoint, request.Address);

        // The body is the receiver-supplied subset alone; absent members stay off the wire.
        var body = JsonNode.Parse(request.Body!)!.AsObject();
        var member = Assert.Single(body);
        Assert.Equal(StreamMemberNames.Description, member.Key);
    }

    [Fact]
    public async Task Create_Conflict_IsAnAnswer_NotAnException()
    {
        // 409 means the stream already exists (SSF 1.0 Section 8.1.1.1); the receiver's move is
        // GET plus PATCH or PUT, so the outcome must reach it as a value.
        var handler = new StubHttpHandler().Enqueue(HttpStatusCode.Conflict);

        Assert.Null(await CreateClient(handler).CreateAsync(
            new CreateStreamRequest(), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Get_AppendsTheStreamIdQuery_AndNotFoundIsNull()
    {
        var handler = new StubHttpHandler()
            .Enqueue(HttpStatusCode.OK, ConfigurationJson)
            .Enqueue(HttpStatusCode.NotFound);
        var client = CreateClient(handler);

        var found = await client.GetAsync("s 1", TestContext.Current.CancellationToken);
        var missing = await client.GetAsync("other", TestContext.Current.CancellationToken);

        Assert.NotNull(found);
        Assert.Null(missing);
        Assert.Equal(
            new Uri("https://tr.example.com/ssf/stream?stream_id=s%201"),
            handler.Requests[0].Address);
    }

    [Fact]
    public async Task List_ReadsTheArray_AndEmptyIsNotAnError()
    {
        var handler = new StubHttpHandler()
            .Enqueue(HttpStatusCode.OK, $"[{ConfigurationJson}]")
            .Enqueue(HttpStatusCode.OK, "[]");
        var client = CreateClient(handler);

        Assert.Single(await client.ListAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await client.ListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ReadBack_AssertingAnotherIssuer_IsRefused()
    {
        // Sections 8.1.1.1-8.1.1.4 require the receiver to confirm the "iss" of every
        // configuration it reads back; skipping it would let a misrouted endpoint bind this
        // receiver to another issuer's stream.
        var handler = new StubHttpHandler().Enqueue(
            HttpStatusCode.OK,
            ConfigurationJson.Replace("https://tr.example.com\",", "https://evil.example.com\","));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await CreateClient(handler).GetAsync("s-1", TestContext.Current.CancellationToken));

        Assert.Contains("evil.example.com", exception.Message);
    }

    [Fact]
    public async Task Update_SpeaksPatch_AndAcceptedIsNull()
    {
        // 202 is "taken but not processed" (SSF 1.0 Section 8.1.1.3): the receiver may repeat
        // the same request later, so the pending state must reach it as a value.
        var handler = new StubHttpHandler()
            .Enqueue(HttpStatusCode.OK, ConfigurationJson)
            .Enqueue(HttpStatusCode.Accepted);
        var client = CreateClient(handler);
        var request = new UpdateStreamRequest { StreamId = "s-1", Description = "renamed" };

        Assert.NotNull(await client.UpdateAsync(request, TestContext.Current.CancellationToken));
        Assert.Null(await client.UpdateAsync(request, TestContext.Current.CancellationToken));

        Assert.All(handler.Requests, recorded => Assert.Equal(HttpMethod.Patch, recorded.Method));
    }

    [Fact]
    public async Task Replace_SpeaksPut()
    {
        var handler = new StubHttpHandler().Enqueue(HttpStatusCode.OK, ConfigurationJson);

        await CreateClient(handler).ReplaceAsync(
            new UpdateStreamRequest { StreamId = "s-1" }, TestContext.Current.CancellationToken);

        Assert.Equal(HttpMethod.Put, Assert.Single(handler.Requests).Method);
    }

    [Fact]
    public async Task Delete_SendsDelete_WithTheStreamIdQuery()
    {
        var handler = new StubHttpHandler().Enqueue(HttpStatusCode.NoContent);

        await CreateClient(handler).DeleteAsync("s-1", TestContext.Current.CancellationToken);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Delete, request.Method);
        Assert.Equal(
            new Uri("https://tr.example.com/ssf/stream?stream_id=s-1"), request.Address);
    }

    [Fact]
    public async Task Status_ReadsAndUpdates_WithAcceptedAsNull()
    {
        var handler = new StubHttpHandler()
            .Enqueue(HttpStatusCode.OK, """{"stream_id": "s-1", "status": "paused"}""")
            .Enqueue(HttpStatusCode.Accepted);
        var client = CreateClient(handler);

        var status = await client.GetStatusAsync("s-1", TestContext.Current.CancellationToken);
        Assert.Equal(StreamStatuses.Paused, status!.Status);

        // The status read carries the REQUIRED stream_id parameter (SSF 1.0 Section 8.1.2.1) -
        // and unlike the configuration endpoint, the status endpoint has no list fallback for a
        // request without it.
        Assert.Equal(
            new Uri("https://tr.example.com/ssf/status?stream_id=s-1"),
            handler.Requests[0].Address);

        Assert.Null(await client.UpdateStatusAsync(
            new StreamStatus { StreamId = "s-1", Status = StreamStatuses.Enabled },
            TestContext.Current.CancellationToken));
        Assert.Equal(Transmitter.StatusEndpoint, handler.Requests[1].Address);
    }

    [Fact]
    public async Task SubjectsAndVerification_RouteToTheirEndpoints_AndThrottlingIsFalse()
    {
        var handler = new StubHttpHandler()
            .Enqueue(HttpStatusCode.OK)
            .Enqueue(HttpStatusCode.NoContent)
            .Enqueue(HttpStatusCode.TooManyRequests);
        var client = CreateClient(handler);

        Assert.True(await client.AddSubjectAsync(
            new AddSubjectRequest { StreamId = "s-1", Subject = new EmailSubject("u@example.com") },
            TestContext.Current.CancellationToken));
        Assert.True(await client.RemoveSubjectAsync(
            new RemoveSubjectRequest { StreamId = "s-1", Subject = new EmailSubject("u@example.com") },
            TestContext.Current.CancellationToken));
        Assert.False(await client.RequestVerificationAsync(
            new VerificationRequest { StreamId = "s-1" }, TestContext.Current.CancellationToken));

        Assert.Equal(Transmitter.AddSubjectEndpoint, handler.Requests[0].Address);
        Assert.Equal(Transmitter.RemoveSubjectEndpoint, handler.Requests[1].Address);
        Assert.Equal(Transmitter.VerificationEndpoint, handler.Requests[2].Address);
    }

    [Fact]
    public async Task MissingAdvertisedEndpoint_FailsLoudly_NamingTheMember()
    {
        var bare = new StreamManagementClient(
            new StubHttpHandler().CreateClient(),
            new TransmitterConfiguration { Issuer = Issuer });

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await bare.RequestVerificationAsync(
                new VerificationRequest { StreamId = "s-1" }, TestContext.Current.CancellationToken));

        Assert.Contains(
            TransmitterConfiguration.ParameterNames.VerificationEndpoint, exception.Message);
    }
}
