// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DocSamples.Stubs;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.DocSamples.Samples;

/// <summary>
/// The compiled copy of the sample documenting how a host replaces the CIBA stub with its own handler.
/// </summary>
/// <remarks>
/// <c>MyDeviceAuthHandler</c> is the integrator's own half and cannot come from the library, so it is a
/// stub here. That is the weak seam of the gate: a stub carrying the name of something the library
/// really ships would satisfy the compiler while hiding the rename this exists to catch, which is why
/// <c>DocSampleTests.NoStubShadowsATypeTheLibraryShips</c> exists.
/// </remarks>
internal static class BackChannelHandlerSample
{
    internal static void Configure(IServiceCollection services)
    {
        // <sample>
        services.AddScoped<IUserDeviceAuthenticationHandler, MyDeviceAuthHandler>();
        services.AddBackChannelAuthentication();
        // </sample>
    }
}
