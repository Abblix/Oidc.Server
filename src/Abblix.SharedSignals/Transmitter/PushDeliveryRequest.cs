// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Text;
using Abblix.SecurityEvents.Delivery;
using Abblix.SharedSignals.Model.Delivery;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The HTTP request that carries one signed SET to a push receiver.
/// </summary>
internal static class PushDeliveryRequest
{
    /// <summary>
    /// Builds the POST of <paramref name="token"/> to the receiver's endpoint.
    /// </summary>
    /// <param name="push">The receiver's delivery configuration.</param>
    /// <param name="token">The signed SET in compact serialization.</param>
    public static HttpRequestMessage Create(PushDeliveryMethod push, string token)
    {
        // "POST ... with a media type of 'application/secevent+jwt'" and a JSON error body to
        // accept back (RFC 8935 Sections 2.1-2.3).
        var request = new HttpRequestMessage(HttpMethod.Post, push.EndpointUrl)
        {
            Content = new StringContent(token, Encoding.UTF8, SecurityEventTokenMediaTypes.SecurityEventToken),
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(MediaTypeNames.Application.Json));

        // "If present, the Transmitter MUST provide this value with every HTTP request to the
        // endpoint_url" (SSF 1.0 Section 6.1.1). The value is the receiver's whole header line,
        // taken as given.
        if (push.AuthorizationHeader is { } authorization)
        {
            request.Headers.TryAddWithoutValidation(
                nameof(HttpRequestHeader.Authorization), authorization);
        }

        return request;
    }
}
