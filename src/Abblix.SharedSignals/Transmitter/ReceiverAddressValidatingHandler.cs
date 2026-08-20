// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Puts <see cref="ReceiverAddressPolicy"/> on every push delivery request, redirects and rebinding included.
/// </summary>
/// <remarks>
/// The delivery endpoint comes from the receiver, so the address has to be judged on the connection the socket
/// actually makes, not only on the URL the receiver configured. The shared base
/// (<see cref="AddressValidatingHttpMessageHandler"/>) refuses redirects and calls the policy immediately before
/// each send; the policy is the same one the sender consults up front, so a statically bad endpoint is refused
/// early and loudly, and a redirect or a rebinding is caught here on the request that would have carried it.
/// </remarks>
/// <param name="addressPolicy">Judges the address of a delivery endpoint.</param>
public sealed class ReceiverAddressValidatingHandler(ReceiverAddressPolicy addressPolicy)
    : AddressValidatingHttpMessageHandler
{
    /// <inheritdoc />
    protected override async Task GuardAsync(Uri requestUri, CancellationToken cancellationToken)
    {
        if (await addressPolicy.RejectionOf(requestUri, cancellationToken) is { } rejection)
        {
            throw new HttpRequestException($"Refusing push delivery to '{requestUri}': {rejection}.");
        }
    }
}
