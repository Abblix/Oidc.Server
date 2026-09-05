// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
