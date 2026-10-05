// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// The settings of an issuer that the license takes at their word about the tenant they serve and its release. Only
/// the server's own settings implement it; settings a host registers do not, so what they answer never takes an issuer
/// or its clients off the count.
/// </summary>
internal interface ILicensedIssuer
{
    /// <summary>
    /// The tenant the issuer serves, counted as one place wherever its address moves; empty on a server without
    /// tenants, and null when the server cannot vouch for the tenant because a catalog of the host's own resolved it.
    /// </summary>
    string? VouchedId { get; }

    /// <summary>
    /// Canceled once the server lets the tenant go, when the issuer and its clients stop counting.
    /// </summary>
    CancellationToken Released { get; }
}
