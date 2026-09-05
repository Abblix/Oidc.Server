// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

// Spelled out rather than left to ImplicitUsings, because this file is compiled into suites that do not enable it.
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Abblix.Tests.Shared;

/// <summary>
/// An origin that fails a set number of times before answering, so a retry is visible as a request count rather
/// than inferred from the presence of a handler.
/// </summary>
/// <param name="failuresBeforeSuccess">How many attempts are refused before one succeeds.</param>
/// <param name="successContent">
/// The JSON body the successful answer carries, for a client that reads one. Null answers with an empty body,
/// which is enough for a client that only checks the status.</param>
public sealed class FlakyOriginHandler(int failuresBeforeSuccess, string? successContent = null)
    : HttpMessageHandler
{
    /// <summary>How many attempts reached the origin.</summary>
    public int Requests { get; private set; }

    /// <inheritdoc />
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Requests++;

        // 503 is what the standard pipeline treats as worth retrying; a 400 would prove nothing, since the
        // pipeline is right not to repeat it.
        if (Requests <= failuresBeforeSuccess)
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

        var response = new HttpResponseMessage(HttpStatusCode.OK);
        if (successContent is not null)
            response.Content = new StringContent(successContent, Encoding.UTF8, "application/json");

        return Task.FromResult(response);
    }
}
