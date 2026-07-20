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
using System.Net.Http.Headers;

namespace Abblix.Oidc.Client.UnitTests.Features.Tokens;

/// <summary>
/// An <see cref="HttpMessageHandler"/> that answers with a canned body and keeps what was sent to it, so a
/// test can assert on the request the client actually built rather than on a model of it.
/// </summary>
public sealed class RecordingHttpMessageHandler : HttpMessageHandler
{
    private readonly string _body;
    private readonly HttpStatusCode _statusCode;

    /// <summary>
    /// Creates the handler with the response it returns to every request.
    /// </summary>
    public RecordingHttpMessageHandler(string body, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        _body = body;
        _statusCode = statusCode;
    }

    /// <summary>
    /// How many requests passed through.
    /// </summary>
    public int RequestCount { get; private set; }

    /// <summary>
    /// The form body of the most recent request.
    /// </summary>
    public string? LastRequestBody { get; private set; }

    /// <summary>
    /// The Authorization header of the most recent request, if it carried one.
    /// </summary>
    public AuthenticationHeaderValue? LastAuthorizationHeader { get; private set; }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        RequestCount++;
        LastAuthorizationHeader = request.Headers.Authorization;
        LastRequestBody = request.Content is null
            ? null
            : await request.Content.ReadAsStringAsync(cancellationToken);

        var response = new HttpResponseMessage(_statusCode)
        {
            Content = new StringContent(_body, System.Text.Encoding.UTF8, "application/json"),
        };

        return response;
    }
}
