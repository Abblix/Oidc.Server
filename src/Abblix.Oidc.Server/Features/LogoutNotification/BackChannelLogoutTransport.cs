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

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// The HTTP transport back-channel logout tokens travel on, to the URI a client registered.
/// </summary>
public static class BackChannelLogoutTransport
{
    /// <summary>
    /// The name the transport's client is registered under, published so a host can configure it without copying
    /// the string: <c>services.AddHttpClient(BackChannelLogoutTransport.HttpClientName)</c> reaches the same client
    /// the sender resolves.
    /// </summary>
    /// <remarks>
    /// The value is the contract's name because this is a typed client, and that is the logical name
    /// <c>AddHttpClient&lt;TClient, TImplementation&gt;</c> gives it. Reference the constant rather than spelling
    /// that rule out at every call site.
    /// </remarks>
    public const string HttpClientName = nameof(ILogoutTokenSender);
}
