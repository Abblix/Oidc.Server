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
using Abblix.SecurityEvents.Delivery;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Receiver;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the poll transport (RFC 8936 Sections 2.2, 2.3): the request travels as posted JSON to
/// the delivery's transmitter-supplied endpoint, and the response comes back as the typed model.
/// </summary>
public class PollClientTests
{
    [Fact]
    public async Task Poll_PostsTheRequest_ToTheDeliveryEndpoint_AndReadsTheResponse()
    {
        var handler = new StubHttpHandler().Enqueue(
            HttpStatusCode.OK,
            """{"sets": {"jti-1": "eyJhbGciOiJSUzI1NiJ9.e30.sig"}, "moreAvailable": true}""");
        var delivery = new PollDeliveryMethod(new Uri("https://tr.example.com/ssf/poll/s-1"));

        var response = await new PollClient(handler.CreateClient()).PollAsync(
            delivery,
            new PollRequest { MaxEvents = 5, Acknowledged = ["jti-0"] },
            TestContext.Current.CancellationToken);

        Assert.Equal("eyJhbGciOiJSUzI1NiJ9.e30.sig", response.Sets["jti-1"]);
        Assert.True(response.MoreAvailable);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(delivery.EndpointUrl, request.Address);

        var body = JsonNode.Parse(request.Body!)!.AsObject();
        Assert.Equal(5, body[PollRequest.ParameterNames.MaxEvents]!.GetValue<int>());
        Assert.Equal("jti-0", body[PollRequest.ParameterNames.Acknowledged]![0]!.GetValue<string>());
    }

    [Fact]
    public async Task Poll_NothingWaiting_IsTheEmptySetsObject()
    {
        // "If there are no outstanding SETs to be transmitted, the JSON object SHALL be empty"
        // (RFC 8936 Section 2.3) - an empty poll is a normal answer, not an error.
        var handler = new StubHttpHandler().Enqueue(HttpStatusCode.OK, """{"sets": {}}""");

        var response = await new PollClient(handler.CreateClient()).PollAsync(
            new Uri("https://tr.example.com/ssf/poll/s-1"),
            new PollRequest(),
            TestContext.Current.CancellationToken);

        Assert.Empty(response.Sets);
        Assert.Null(response.MoreAvailable);
    }
}
