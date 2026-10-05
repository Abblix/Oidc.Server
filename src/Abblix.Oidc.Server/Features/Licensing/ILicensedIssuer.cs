// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// The settings of an issuer whose tenant and release the license takes as they say. Only the server's own settings
/// implement it, and settings a host registers cannot, so what a host's implementation answers never takes an issuer
/// or its clients off the count.
/// </summary>
internal interface ILicensedIssuer
{
    /// <summary>
    /// The tenant the issuer serves, counted as one place wherever its address moves.
    /// </summary>
    string Id { get; }

    /// <summary>
    /// Canceled once the server lets the tenant go, when the issuer and its clients stop counting.
    /// </summary>
    CancellationToken Released { get; }
}
