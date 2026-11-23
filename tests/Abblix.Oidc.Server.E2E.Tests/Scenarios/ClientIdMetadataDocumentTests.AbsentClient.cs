// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class ClientIdMetadataDocumentTests
{
    private const string UnknownClientId = "unknown-client";

    /// <summary>
    /// Section 6.1 has the server "MUST NOT redirect the user agent to the client" when the document "could not be
    /// retrieved or was invalid", and sections 5 and 6 abort the authorization request "with invalid_client"; a client
    /// no store holds is no client at all and is refused as an unauthorized one. The pushed authorization request
    /// endpoint authenticates the client first, as RFC 9126 section 2.1 has it, and answers as the token endpoint does.
    /// </summary>
    [Theory]
    [InlineData(Arrival.Query, false, HttpStatusCode.BadRequest, ErrorCodes.UnauthorizedClient)]
    [InlineData(Arrival.Query, true, HttpStatusCode.BadRequest, ErrorCodes.InvalidClient)]
    [InlineData(Arrival.RequestObject, false, HttpStatusCode.BadRequest, ErrorCodes.UnauthorizedClient)]
    [InlineData(Arrival.RequestObject, true, HttpStatusCode.BadRequest, ErrorCodes.InvalidClient)]
    [InlineData(Arrival.RequestUri, false, HttpStatusCode.BadRequest, ErrorCodes.UnauthorizedClient)]
    [InlineData(Arrival.RequestUri, true, HttpStatusCode.BadRequest, ErrorCodes.InvalidClient)]
    [InlineData(Arrival.Pushed, false, HttpStatusCode.Unauthorized, ErrorCodes.InvalidClient)]
    [InlineData(Arrival.Pushed, true, HttpStatusCode.Unauthorized, ErrorCodes.InvalidClient)]
    public async Task AnAbsentClient_IsRefusedWithoutARedirect(
        Arrival arrival,
        bool namedByUrl,
        HttpStatusCode status,
        string error)
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await SendAsync(client, discovery, arrival, namedByUrl ? ClientId : UnknownClientId);

        Assert.Equal(status, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal(error, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// A request pushed while the client's document was valid, followed after the document was refused: the request is
    /// read back, and the client it names is judged again as the authorization request is processed (RFC 9126 section
    /// 4), so it is refused as any client whose document is refused.
    /// </summary>
    [Fact]
    public async Task AClientRefusedAfterItsRequestWasPushed_IsAnInvalidClient_WithoutARedirect()
    {
        _origin.Serve(ClientId, PublicClientDocument().ToJsonString(), "no-store");
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var pushed = await PushAuthorizationRequestAsync(
            client, discovery, CodeFlowParameters(ClientId, GeneratePkcePair().Challenge));
        _origin.Answer(ClientId, () => new HttpResponseMessage(HttpStatusCode.NotFound));

        using var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = ClientId,
                [AuthorizationRequest.Parameters.RequestUri] =
                    pushed[PushedAuthorizationResponse.Parameters.RequestUri]!.GetValue<string>(),
            }),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal(ErrorCodes.InvalidClient, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// RFC 9126 section 4: where pushed requests are the only way in, the server "will refuse, using the
    /// "invalid_request" error code, to process any request to the authorization endpoint that does not have a
    /// "request_uri" parameter with a value obtained from the PAR endpoint" - decided before the client is looked up,
    /// so no document is fetched.
    /// </summary>
    [Fact]
    public async Task ARequestNotPushedWherePushingIsRequired_IsRefusedBeforeTheClientIsJudged()
    {
        await using var host = CreateHost(options => options.RequirePushedAuthorizationRequests = true);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await SendAsync(client, discovery, Arrival.Query);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequest, await ErrorResponseReader.ErrorCodeOf(response));
        Assert.Equal(0, _origin.RequestsTo(ClientId));
    }

    /// <summary>
    /// A request_uri naming no pushed request is refused as an invalid one (RFC 9126 section 4) before the client it
    /// names is looked up, so no document is fetched.
    /// </summary>
    [Fact]
    public async Task AnUnknownPushedRequest_IsRefusedBeforeTheClientIsJudged()
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = ClientId,
                [AuthorizationRequest.Parameters.RequestUri] = RequestUrn.Prefix + "unknown",
            }),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequestUri, await ErrorResponseReader.ErrorCodeOf(response));
        Assert.Equal(0, _origin.RequestsTo(ClientId));
    }
}
