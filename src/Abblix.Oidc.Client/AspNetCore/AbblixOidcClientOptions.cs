// Abblix OIDC Client Library
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

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Client.AspNetCore;

/// <summary>
/// How the authentication handler is wired into the application.
/// </summary>
/// <remarks>
/// Only what the host owns: where the callback lands and where the signed-in user is kept. What the protocol
/// owns - the client identifier, the flow, the scopes, the redirection endpoint, how the client authenticates
/// - is configured on the client itself, so there is one place to look for each question and no pair of
/// settings that can disagree.
/// </remarks>
public sealed class AbblixOidcClientOptions : RemoteAuthenticationOptions
{
    /// <summary>
    /// Creates the options with the defaults a host can start from.
    /// </summary>
    /// <remarks>
    /// <see cref="RemoteAuthenticationOptions.CallbackPath"/> is the path half of the <c>redirect_uri</c>
    /// registered with the provider. It is stated to the handler as well as to the client because the
    /// handler has to recognise the callback before any of the client's own machinery is reached, and a
    /// request is recognised by its path.
    /// </remarks>
    public AbblixOidcClientOptions()
    {
        CallbackPath = new PathString("/signin-oidc");

        // The base class leaves this null and builds a default only when the handler runs, so a host
        // configuring an event the obvious way - options.Events.OnRemoteFailure = ... - would meet a null
        // reference while the application starts. Every framework handler that carries events creates one
        // here for the same reason.
        Events = new RemoteAuthenticationEvents();
    }
}
