// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// A <see cref="Result{AuthSession, AuthError}"/> wrapping the created authentication session information.
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
    public Task<Result<AuthSession, OidcError>> InitiateAuthenticationAsync(ValidBackChannelAuthenticationRequest request)
    {
        throw new NotImplementedException(
            "CIBA (Client-Initiated Backchannel Authentication) is not configured yet. " +
            "To enable CIBA feature, you must implement IUserDeviceAuthenticationHandler, e.g.: \n\n" +
            "    public class MyDeviceAuthHandler : IUserDeviceAuthenticationHandler { ... }\n\n" +
            "and register it in your DI container *before* calling AddBackChannelAuthentication() " +
            "or AddOidcServices(), for example:\n\n" +
            "    services.AddScoped<IUserDeviceAuthenticationHandler, MyDeviceAuthHandler>();\n" +
            "    services.AddBackChannelAuthentication();"
        );
    }
}
