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

namespace Abblix.Oidc.Client.AspNetCore;

/// <summary>
/// Adds the Abblix OIDC client as an authentication scheme.
/// </summary>
public static class AuthenticationBuilderExtensions
{
    /// <summary>
    /// The scheme name used when a host does not name one.
    /// </summary>
    public const string DefaultScheme = "AbblixOidc";

    /// <summary>
    /// Adds the handler that signs users in through an OpenID Provider.
    /// </summary>
    /// <param name="builder">The authentication builder to add the scheme to.</param>
    /// <param name="configureOptions">Where the callback lands and where the signed-in user is kept.</param>
    /// <returns>The same builder, so calls chain.</returns>
    /// <remarks>
    /// This adds the scheme only. The client itself - which provider, which flow, which scopes, how the
    /// client authenticates - is registered separately on the service collection, so a host that also talks
    /// to the client directly is talking to the same one the handler uses.
    /// A sign-in scheme is needed beside this one: the handler signs the user in there once, and that scheme
    /// is what every later request reads.
    /// </remarks>
    public static AuthenticationBuilder AddAbblixOidcClient(
        this AuthenticationBuilder builder, Action<AbblixOidcClientOptions> configureOptions)
        => builder.AddAbblixOidcClient(DefaultScheme, configureOptions);

    /// <summary>
    /// Adds the handler under a name of the host's choosing, for an application that talks to more than one
    /// provider.
    /// </summary>
    /// <param name="builder">The authentication builder to add the scheme to.</param>
    /// <param name="authenticationScheme">The name of the scheme.</param>
    /// <param name="configureOptions">Where the callback lands and where the signed-in user is kept.</param>
    /// <returns>The same builder, so calls chain.</returns>
    public static AuthenticationBuilder AddAbblixOidcClient(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<AbblixOidcClientOptions> configureOptions)
        => builder.AddRemoteScheme<AbblixOidcClientOptions, AbblixOidcClientHandler>(
            authenticationScheme, displayName: null, configureOptions);
}
