// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Checks whether a client's configuration can actually satisfy the profile it selects, so a
/// contradiction surfaces loudly at registration or startup instead of as a per-request rejection
/// the operator has to reverse-engineer. The runtime validators already tighten a request to the
/// profile; this is the fail-loud companion that catches static configuration that can never produce
/// a conformant flow in the first place.
/// </summary>
public static class SecurityProfileConsistency
{
    /// <summary>
    /// Returns the human-readable violations that prevent a client with the given registered response
    /// types from satisfying the effective profile, or an empty list when the configuration is
    /// self-consistent. The check operates on response types because that is the one part of a FAPI
    /// client the profile cannot silently fix at request time: a client that never permits the
    /// authorization-code response type, or that permits an implicit/hybrid one, is misconfigured
    /// rather than merely tightened.
    /// </summary>
    /// <param name="allowedResponseTypes">The response-type combinations the client is registered for.</param>
    /// <param name="profile">The effective profile governing the client.</param>
    public static IReadOnlyList<string> FindViolations(
        IReadOnlyList<string[]> allowedResponseTypes,
        ClientSecurityProfile profile)
    {
        if (!SecurityProfileRequirements.Resolve(profile).RequireCodeResponseTypeOnly)
            return [];

        var violations = new List<string>();

        // A single-element "code" entry, matched case-insensitively to stay consistent with the
        // token-bearing check below (both ultimately use HasFlag's OrdinalIgnoreCase comparison).
        var allowsCode = allowedResponseTypes.Any(
            responseType => responseType is { Length: 1 } && responseType.HasFlag(ResponseTypes.Code));
        if (!allowsCode)
        {
            violations.Add(
                "the FAPI 2.0 Security Profile requires the authorization-code response type, " +
                "but the client does not allow it");
        }

        if (allowedResponseTypes.Any(responseType => responseType.ReturnsTokenFromAuthorization()))
        {
            violations.Add(
                "the FAPI 2.0 Security Profile forbids implicit and hybrid response types, " +
                "but the client allows a response type that returns a token from the authorization endpoint");
        }

        return violations;
    }
}
