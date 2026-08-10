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

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// The HTTP transport CIBA ping and push notifications travel on, to the endpoint a client registered.
/// </summary>
public static class BackChannelNotificationTransport
{
    /// <summary>
    /// The name the transport's client is registered under, published so a host can configure it without copying
    /// the string: <c>services.AddHttpClient(BackChannelNotificationTransport.HttpClientName)</c> reaches the same
    /// client the delivery service resolves, and whatever it chains - a resilience pipeline, a proxy - applies to
    /// every notification.
    /// </summary>
    /// <remarks>
    /// Whatever a host chains runs OUTSIDE the SSRF validation, because that validation is the client's primary
    /// handler and therefore the innermost one. So every attempt a resilience pipeline makes is validated afresh -
    /// which is what the address of a client-supplied endpoint requires, since it can start resolving to an
    /// internal one between attempts - and no ordering of the host's own calls can move the check out of the way.
    /// <para>
    /// The value is the delivery service's type name because that is what shipped, and a host already configuring
    /// the client spells it literally. Changing it would break such a host in the one way nothing reports: the
    /// configuration would bind to a client no longer resolved, leaving the build green and the pipeline gone.
    /// </para>
    /// </remarks>
    public const string HttpClientName = nameof(HttpNotificationDeliveryService);
}
