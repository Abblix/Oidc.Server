// Abblix OIDC Client Library
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
using System.Net.Http.Headers;

namespace Abblix.Oidc.Client.UnitTests.Features.Discovery;

/// <summary>
/// An <see cref="HttpMessageHandler"/> that answers with a canned body and records what was asked for, so a
/// test can assert both the address the client built and how many times it went to the network.
/// </summary>
public sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private string _body;
    private HttpStatusCode _statusCode;

    /// <summary>
    /// Creates the handler with the response it will return until told otherwise.
    /// </summary>
    public StubHttpMessageHandler(string body, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        _body = body;
        _statusCode = statusCode;
    }

    /// <summary>
    /// Every address requested through this handler, in order.
    /// </summary>
    public List<Uri> RequestedAddresses { get; } = [];

    /// <summary>
    /// Changes the response returned from the next request onwards.
    /// </summary>
    public void RespondWith(string body, HttpStatusCode statusCode)
    {
        _body = body;
        _statusCode = statusCode;
    }

    /// <inheritdoc />
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        RequestedAddresses.Add(request.RequestUri!);

        var response = new HttpResponseMessage(_statusCode)
        {
            Content = new StringContent(_body),
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        return Task.FromResult(response);
    }
}
