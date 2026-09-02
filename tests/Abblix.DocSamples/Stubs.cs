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

namespace Abblix.DocSamples.Stubs;

/// <summary>
/// The integrator's own half of a sample, standing in for code this library does not ship.
/// </summary>
/// <remarks>
/// Every type in this namespace is a liability, not an asset. A sample calls into something the reader
/// writes - a device-authentication handler, a notification service - and that something has to exist
/// for the sample to compile, but a stub whose NAME collides with a type the library really ships would
/// satisfy the compiler while hiding the very rename this project exists to catch.
/// <para>
/// So the namespace is the boundary: <c>DocSampleTests.NoStubShadowsATypeTheLibraryShips</c> reads every
/// type declared here by reflection and refuses any whose name the shipped assembly also exports. Adding
/// a stub outside this namespace puts it beyond that check, which is the one way to defeat the gate
/// quietly.
/// </para>
/// </remarks>
internal sealed class MyDeviceAuthHandler : IUserDeviceAuthenticationHandler
{
    /// <inheritdoc />
    public Task<Result<AuthSession, OidcError>> InitiateAuthenticationAsync(
        ValidBackChannelAuthenticationRequest request)
    {
        // A body the compiler accepts and nothing calls. What the sample documents is the REGISTRATION
        // of a handler, not what a handler does, so inventing plausible behaviour here would add text
        // no doc comment carries and nothing verifies.
        throw new NotSupportedException(
            $"{nameof(MyDeviceAuthHandler)} stands in for an integrator's handler and is never invoked.");
    }
}
