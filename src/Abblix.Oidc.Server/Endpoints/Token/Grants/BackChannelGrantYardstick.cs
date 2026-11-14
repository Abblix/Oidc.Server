// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Model;
using StoredRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// What a backchannel authentication request asked for, read once before the processor is handed the request.
/// </summary>
/// <remarks>
/// The comparison after redemption exists because what is stored can change between the two checks,
/// and taking its yardstick from the same object the processor holds would let one change move both
/// sides together.
/// </remarks>
/// <param name="Request">The stored request as it was read.</param>
/// <param name="NamedEndUsers">A copy of the end users the request named, or null when it named nobody.</param>
/// <param name="RecordedLevels">A copy of the authentication levels the request requires, or null.</param>
/// <param name="RequiredClaims">The claims the request asked for, which may make an acr essential.</param>
internal sealed record BackChannelGrantYardstick(
    StoredRequest Request,
    string[]? NamedEndUsers,
    string[]? RecordedLevels,
    RequestedClaims? RequiredClaims)
{
    /// <summary>
    /// Reads the yardstick off the stored request, copying what a host could change in place.
    /// </summary>
    public static BackChannelGrantYardstick Of(StoredRequest request) => new(
        request,
        request.RequestedSubjects is { } named ? [..named] : null,
        request.RequiredAuthContextClassRefs is { } recorded ? [..recorded] : null,
        request.AuthorizedGrant.Context.RequestedClaims);
}
