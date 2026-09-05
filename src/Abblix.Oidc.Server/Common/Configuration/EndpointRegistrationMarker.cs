// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Records which opt-in OIDC endpoints have had their feature services registered via the corresponding
/// <c>AddX()</c> call. It is order-independent: every <c>AddX()</c> contributes its flag through
/// <c>Configure</c>, so the accumulated set is available regardless of whether the opt-in ran before or after
/// <c>AddOidcCore</c>. <see cref="EnabledEndpointsRegistrationValidator"/> reads it to fail fast when
/// <see cref="OidcOptions.EnabledEndpoints"/> advertises an opt-in endpoint whose handler was never registered.
/// </summary>
internal sealed class EndpointRegistrationMarker
{
    /// <summary>The opt-in endpoints whose feature services are actually registered.</summary>
    public OidcEndpoints Registered { get; set; }
}