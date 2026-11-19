// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

// Spelled out rather than left to ImplicitUsings, because this file is compiled into suites that do not enable it.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Abblix.Tests.Shared;

/// <summary>
/// Stands in for the web servers clients publish their metadata documents on: each URL answers what the test set for
/// it, and every request is recorded.
/// </summary>
public sealed class MetadataDocumentOrigin : HttpMessageHandler
{
    private readonly ConcurrentDictionary<string, Func<Task<HttpResponseMessage>>> _answers = new(StringComparer.Ordinal);
    private readonly ConcurrentQueue<HttpRequestMessage> _requests = new();

    /// <summary>
    /// Serves <paramref name="json"/> at <paramref name="url"/> as <c>application/json</c>, with
    /// <paramref name="cacheControl"/> as its Cache-Control header when given.
    /// </summary>
    public void Serve(string url, string json, string? cacheControl = null)
        => Answer(url, () =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
            if (cacheControl is not null)
                response.Headers.TryAddWithoutValidation("Cache-Control", cacheControl);

            return response;
        });

    /// <summary>
    /// Answers <paramref name="url"/> with whatever <paramref name="answer"/> builds, once per request.
    /// </summary>
    public void Answer(string url, Func<HttpResponseMessage> answer)
        => _answers[url] = () => Task.FromResult(answer());

    /// <summary>
    /// Answers <paramref name="url"/> with whatever <paramref name="answer"/> completes with, once per request, so a test
    /// can hold a request open without holding a thread.
    /// </summary>
    public void AnswerAsync(string url, Func<Task<HttpResponseMessage>> answer) => _answers[url] = answer;

    /// <summary>
    /// Fails every request to <paramref name="url"/> as an unreachable host does.
    /// </summary>
    public void Unreachable(string url) => Answer(url, () => throw new HttpRequestException("unreachable"));

    /// <summary>The requests that reached the origin, in order.</summary>
    public IReadOnlyCollection<HttpRequestMessage> Requests => _requests;

    /// <summary>How many requests reached <paramref name="url"/>.</summary>
    public int RequestsTo(string url)
    {
        var count = 0;
        foreach (var request in _requests)
        {
            if (string.Equals(request.RequestUri?.AbsoluteUri, url, StringComparison.Ordinal))
                count++;
        }

        return count;
    }

    /// <inheritdoc />
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        _requests.Enqueue(request);
        var url = request.RequestUri?.AbsoluteUri ?? string.Empty;
        return _answers.TryGetValue(url, out var answer)
            ? answer()
            : Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
