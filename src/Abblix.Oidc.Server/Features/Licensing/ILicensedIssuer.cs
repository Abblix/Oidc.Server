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
    /// The tenant serving <paramref name="issuer"/>, counted as one place wherever its address moves; null when the
    /// server cannot vouch for it: a catalog of the host's own resolved the tenant, or the server's own catalog has not
    /// served this creation of the tenant at <paramref name="issuer"/>.
    /// </summary>
    /// <param name="issuer">The issuer a token names.</param>
    string? VouchedId(string issuer);

    /// <summary>
    /// Canceled once the server lets the tenant go, when the issuer and its clients stop counting.
    /// </summary>
    CancellationToken Released { get; }
}
