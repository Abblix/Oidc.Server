// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
