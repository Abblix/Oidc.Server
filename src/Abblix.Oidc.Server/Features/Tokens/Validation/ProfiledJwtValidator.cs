// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// The one door to <see cref="IJsonWebTokenValidator"/> for what this server accepts: it stamps every validation with
/// the signature and key management algorithms the security profile in force admits, on top of what the caller asks.
/// </summary>
/// <remarks>
/// FAPI 1.0 Part 2 section 8.6: "For JWS, both clients and authorization servers shall use PS256 or ES256 algorithms";
/// section 8.6.1: "For JWE, both clients and authorization servers shall not use the RSA1_5 algorithm"; FAPI 2.0 section
/// 5.4.1, "when creating or processing JWTs". A caller's own signature list, such as the asymmetric-only one of a DPoP
/// proof, is narrowed to what the profile also admits, and a caller's own judgement of a key management algorithm runs
/// beside the profile's, so a caller can neither widen the profile nor lose its own rule.
/// <para>
/// Public, though nothing outside this library needs it, because the types that take it are public with public
/// constructors, which the container requires.
/// </para>
/// </remarks>
/// <param name="validator">Validates the token once the parameters carry the profile's algorithms.</param>
public sealed class ProfiledJwtValidator(IJsonWebTokenValidator validator)
{
    /// <summary>
    /// Validates <paramref name="jwt"/> under <paramref name="parameters"/>, held to the algorithms
    /// <paramref name="profile"/> admits.
    /// </summary>
    /// <param name="profile">The controls in force for what is accepted.</param>
    /// <param name="jwt">The token to validate.</param>
    /// <param name="parameters">The caller's validation, its own algorithm rules included.</param>
    public async Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
        SecurityProfileRequirements profile,
        string jwt,
        ValidationParameters parameters)
    {
        var signing = Intersection(parameters.AllowedSigningAlgorithms, profile.SigningAlgorithmsAdmitted());

        // The validator reads an empty list as no list, so lists sharing nothing refuse the token here
        if (signing is { Count: 0 })
        {
            return new JwtValidationError(
                JwtError.InvalidAlgorithm,
                "No signature algorithm is admitted both on this validation path and by the security profile in force");
        }

        var callers = parameters.ValidateKeyManagementAlgorithm;
        return await validator.ValidateAsync(jwt, parameters with
        {
            AllowedSigningAlgorithms = signing,

            // The caller's judgement first, so one that records each layer it is asked about sees every layer
            ValidateKeyManagementAlgorithm = callers is null
                ? profile.PermitsKeyManagementAlgorithm
                : algorithm => callers(algorithm) && profile.PermitsKeyManagementAlgorithm(algorithm),
        });
    }

    /// <summary>
    /// The algorithms both lists admit, where an absent list admits any.
    /// </summary>
    private static IReadOnlySet<string>? Intersection(IReadOnlySet<string>? callers, IReadOnlySet<string>? profiles)
        => (callers, profiles) switch
        {
            ({ Count: > 0 } a, { } b) => a.Where(b.Contains).ToHashSet(StringComparer.Ordinal),
            ({ Count: > 0 } a, null) => a,
            (_, { } b) => b,
            _ => callers,
        };
}
