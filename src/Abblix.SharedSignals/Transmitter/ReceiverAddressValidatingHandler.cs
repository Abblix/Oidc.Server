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
