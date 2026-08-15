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
