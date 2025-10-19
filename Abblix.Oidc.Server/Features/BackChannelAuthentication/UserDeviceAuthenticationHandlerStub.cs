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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// Stub implementation of <see cref="IUserDeviceAuthenticationHandler"/>
/// for Client-Initiated Backchannel Authentication (CIBA).
/// </summary>
/// <remarks>
/// This stub always throws <see cref="NotImplementedException"/> to indicate that you must provide your own
/// implementation of <see cref="IUserDeviceAuthenticationHandler"/> and register it in DI before enabling CIBA.
/// </remarks>
internal class UserDeviceAuthenticationHandlerStub : IUserDeviceAuthenticationHandler
{
    /// <summary>
    /// Initiates the back-channel authentication process for a user’s device.
    /// </summary>
    /// <param name="request">
    /// A validated <see cref="ValidBackChannelAuthenticationRequest"/> containing the CIBA parameters
    /// (e.g. client ID, login hint, scope, etc.).
    /// </param>
    /// <returns>
    /// A <see cref="Result{AuthSession, RequestError}"/> wrapping the created authentication session information.
    /// </returns>
    /// <exception cref="NotImplementedException">
    /// Always thrown to indicate CIBA is not configured. To enable CIBA:
    /// <list type="bullet">
    ///   <item>
    ///     Implement <see cref="IUserDeviceAuthenticationHandler"/>, for example:
    ///     <c>public class MyDeviceAuthHandler : IUserDeviceAuthenticationHandler { ... }</c>
    ///   </item>
    ///   <item>
    ///     Register your implementation in the DI container *before* calling <c>AddBackChannelAuthentication()</c>
    ///     or <c>AddOidcServices()</c>:
    ///     <code>
    ///     services.AddScoped&lt;IUserDeviceAuthenticationHandler, MyDeviceAuthHandler&gt;();
    ///     services.AddBackChannelAuthentication();
    ///     </code>
    ///   </item>
    ///   <item>
    ///     Alternatively, call <c>builder.Services.AddCiba()</c> to pull in CIBA services and stubs,
    ///     then override with your own handler registration.
    ///   </item>
    /// </list>
    /// </exception>
    public Task<Result<AuthSession, RequestError>> InitiateAuthenticationAsync(ValidBackChannelAuthenticationRequest request)
    {
        throw new NotImplementedException(
            "CIBA (Client‐Initiated Backchannel Authentication) is not configured yet. " +
            "To enable CIBA feature, you must implement IUserDeviceAuthenticationHandler, e.g.: \n\n" +
            "    public class MyDeviceAuthHandler : IUserDeviceAuthenticationHandler { ... }\n\n" +
            "and register it in your DI container *before* calling AddBackChannelAuthentication() " +
            "or AddOidcServices(), for example:\n\n" +
            "    services.AddScoped<IUserDeviceAuthenticationHandler, MyDeviceAuthHandler>();\n" +
            "    services.AddBackChannelAuthentication();"
        );
    }
}
