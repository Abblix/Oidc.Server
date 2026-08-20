// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.RequestFetching;

/// <summary>
/// Resolves a CIBA request by enriching the raw incoming model with parameters obtained from
/// out-of-band sources, most notably a signed JWT Request Object. The validation pipeline runs
/// against the resolved request, not the raw one.
/// </summary>
public interface IBackChannelAuthenticationRequestFetcher
{
    /// <summary>
    /// Resolves the effective <see cref="BackChannelAuthenticationRequest"/>, merging in parameters from
    /// any external source the implementation knows how to read.
    /// </summary>
    /// <param name="request">The raw backchannel authentication request as parsed from the wire.</param>
    /// <returns>The resolved request on success, or an <see cref="OidcError"/> describing why fetching
    /// or signature/structure validation of the external source failed.</returns>
    Task<Result<BackChannelAuthenticationRequest, OidcError>> FetchAsync(BackChannelAuthenticationRequest request);
}
