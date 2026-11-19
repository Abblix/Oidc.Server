// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Utils;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// The transport of a client's metadata document holds to the special-purpose address registries as written
/// (draft-ietf-oauth-client-id-metadata-document section 10.7), the NAT64 prefix included, where every other fetch lets
/// NAT64 reach the public address it carries.
/// </summary>
public class ClientIdMetadataDocumentGuardTests
{
    private const string Url = "https://client.example.com/metadata.json";

    [Theory]
    [InlineData("64:ff9b::808:808", false, true)]
    [InlineData("64:ff9b::808:808", true, false)]
    [InlineData("2001:4860:4860::8888", false, true)]
    [InlineData("2001:4860:4860::8888", true, true)]
    [InlineData("10.0.0.7", true, false)]
    public async Task AResolvedAddress_IsReachedOnlyWhereTheGuardAllowsIt(string resolved, bool documentGuard, bool reached)
    {
        var options = Options.Create(new SecureHttpFetchOptions());
        var validator = new SecureUriValidator(options, NullLogger<SecureUriValidator>.Instance);
        ResolveHostDelegate resolve = (_, _) => Task.FromResult(new[] { IPAddress.Parse(resolved) });
        var transport = new Answering();
        SsrfValidatingHttpMessageHandler guard = documentGuard
            ? new ClientIdMetadataDocumentGuard(options, validator, resolve)
            : new SsrfValidatingHttpMessageHandler(options, validator, resolve);
        guard.InnerHandler!.Dispose();
        guard.InnerHandler = transport;

        using var invoker = new HttpMessageInvoker(guard);
        var sent = await Record.ExceptionAsync(() => invoker.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, Url), TestContext.Current.CancellationToken));

        Assert.Equal(reached, transport.Reached);
        Assert.Equal(reached, sent is null);
    }

    private sealed class Answering : HttpMessageHandler
    {
        public bool Reached { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Reached = true;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
