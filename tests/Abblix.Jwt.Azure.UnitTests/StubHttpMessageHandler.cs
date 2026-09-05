// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text;

namespace Abblix.Jwt.Azure.UnitTests;

/// <summary>
/// Records the requests the Azure SDK sends through its transport and returns the canned response the responder
/// builds, so <see cref="KeyVaultClient"/> is exercised against Key Vault wire shapes without a live vault.
/// </summary>
internal sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
    : HttpMessageHandler
{
    public List<HttpRequestMessage> Requests { get; } = [];
    public HttpRequestMessage? LastRequest => Requests.Count == 0 ? null : Requests[^1];

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        return Task.FromResult(responder(request));
    }

    public static HttpResponseMessage Json(HttpStatusCode status, string json)
        => new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
}