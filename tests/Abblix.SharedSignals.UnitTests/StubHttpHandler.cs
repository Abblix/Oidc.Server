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
using System.Net.Mime;
using System.Text;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// A scripted HTTP handler for driving the receiver clients: answers each request with the next
/// enqueued response and records what was asked - method, address and body - since the request
/// content is gone once the client disposes the message.
/// </summary>
internal sealed class StubHttpHandler : HttpMessageHandler
{
    private readonly Queue<(HttpStatusCode Status, string? Json, string MediaType)> _responses = new();

    public List<(HttpMethod Method, Uri? Address, string? Body)> Requests { get; } = [];

    public StubHttpHandler Enqueue(
        HttpStatusCode status,
        string? json = null,
        string mediaType = MediaTypeNames.Application.Json)
    {
        _responses.Enqueue((status, json, mediaType));
        return this;
    }

    public HttpClient CreateClient() => new(this, disposeHandler: false);

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = request.Content is null
            ? null
            : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Add((request.Method, request.RequestUri, body));

        var (status, json, mediaType) = _responses.Dequeue();
        var response = new HttpResponseMessage(status);
        if (json is not null)
        {
            response.Content = new StringContent(json, Encoding.UTF8, mediaType);
        }

        return response;
    }
}
