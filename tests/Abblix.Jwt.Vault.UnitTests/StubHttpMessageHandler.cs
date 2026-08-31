// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text;
using System.Text.Json;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// Test double for <see cref="HttpMessageHandler"/>: records the request it received and returns the canned
/// response the supplied responder builds, so the Vault clients in this suite are exercised against Vault's
/// wire shapes without a live server.
/// </summary>
internal sealed class StubHttpMessageHandler(
    Func<HttpRequestMessage, string, HttpResponseMessage> responder) : HttpMessageHandler
{
    public HttpRequestMessage? LastRequest { get; private set; }
    public string? LastRequestBody { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequest = request;
        LastRequestBody = request.Content is null
            ? null
            : await request.Content.ReadAsStringAsync(cancellationToken);
        return responder(request, LastRequestBody ?? string.Empty);
    }

    /// <summary>Builds a JSON response with the given status from an object serialized as-is (no camel casing).</summary>
    public static HttpResponseMessage Json(HttpStatusCode status, object body)
        => new(status)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
        };
}
