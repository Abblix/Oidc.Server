// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;

namespace Abblix.Utils;

/// <summary>
/// The message-handler half of protecting a server-initiated request whose address came from outside: it refuses
/// redirects and re-checks the address immediately before every send, leaving only the policy - which addresses
/// are refused - to the derived handler.
/// </summary>
/// <remarks>
/// Two properties make this the right place for the check rather than a pre-flight in front of the client.
/// <para>
/// Redirects are not followed. A receiver that answers a delivery with a 3xx to an internal address would
/// otherwise have the request re-sent there, past any address the caller vetted, so this is the difference
/// between a check and a bypass. With the follow disabled the 3xx comes back as an ordinary non-success response
/// and the caller decides what to do with it.
/// </para>
/// <para>
/// The address is judged here, one call before the connection, rather than only when the request was scheduled.
/// A name that resolved to a public address a moment ago can resolve to an internal one now, so the resolution a
/// derived handler performs in <see cref="GuardAsync"/> is the one whose answer the socket actually uses.
/// </para>
/// </remarks>
public abstract class AddressValidatingHttpMessageHandler : DelegatingHandler
{
    /// <summary>
    /// Builds the handler over a primary transport that follows no redirects and decompresses nothing.
    /// </summary>
    protected AddressValidatingHttpMessageHandler()
        : base(new HttpClientHandler
        {
            // Redirects are the bypass this whole type exists to stop: a followed 3xx reaches an address nothing
            // vetted. Disabled, the 3xx surfaces as a response the caller handles.
            AllowAutoRedirect = false,

            // No ambient credentials, so a request cannot authenticate to an internal server by accident.
            UseDefaultCredentials = false,

            // No automatic decompression, so a hostile response cannot spend the caller's memory on a bomb.
            AutomaticDecompression = DecompressionMethods.None,
        })
    {
    }

    /// <summary>
    /// Judges the request's address and throws when it may not be reached. Returning normally lets the send
    /// proceed.
    /// </summary>
    /// <param name="requestUri">The address this request is about to reach.</param>
    /// <param name="cancellationToken">Cancels the check, including any name resolution it performs.</param>
    protected abstract Task GuardAsync(Uri requestUri, CancellationToken cancellationToken);

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var requestUri = request.RequestUri
            ?? throw new InvalidOperationException("A request through this handler must carry a target URI.");

        await GuardAsync(requestUri, cancellationToken);
        return await base.SendAsync(request, cancellationToken);
    }
}
