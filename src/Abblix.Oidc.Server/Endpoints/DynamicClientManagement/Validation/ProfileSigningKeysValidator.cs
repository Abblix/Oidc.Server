// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Under a security profile admitting only certain signature algorithms (FAPI 1.0 Part 2 section 8.6, FAPI 2.0 section
/// 5.4.1), gives a registration naming no algorithm for its ID tokens and JWT authorization responses the first
/// admitted one a signing key of the tenant can produce, and refuses with <c>invalid_client_metadata</c> a
/// registration whose algorithms, named or given, no such key produces.
/// </summary>
/// <remarks>
/// Decided against the tenant's keys rather than against the list alone: an algorithm the list admits and no key
/// produces is accepted at registration and fails when the first ID token is signed, as a server error the client can
/// do nothing about.
/// </remarks>
/// <param name="keys">The tenant's signing keys.</param>
public class ProfileSigningKeysValidator(IAuthServiceKeysProvider keys) : IClientRegistrationContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(TenantDefinition tenant, ClientRegistrationValidationContext context)
    {
        var requirements = SecurityProfileRequirements.Resolve(tenant.DefaultSecurityProfile);
        if (!requirements.RequireFapiSigningAlgorithms)
            return null;

        var signingKeys = await keys.GetSigningKeys(tenant).ToArrayAsync();
        bool Produces(string algorithm) => Array.Exists(signingKeys, key => key.CanPerform(algorithm));

        var request = context.Request;
        if (request.IdTokenSignedResponseAlg is null || request.AuthorizationSignedResponseAlg is null)
        {
            if (SecurityProfileRequirements.FapiSigningAlgorithmProducedBy(signingKeys) is not { } given)
            {
                return ErrorFactory.InvalidClientMetadata(
                    "No signing key of this server produces " +
                    $"{string.Join(" or ", SecurityProfileRequirements.FapiSigningAlgorithms)}, which its security " +
                    "profile admits alone");
            }

            request = request with
            {
                IdTokenSignedResponseAlg = request.IdTokenSignedResponseAlg ?? given,
                AuthorizationSignedResponseAlg = request.AuthorizationSignedResponseAlg ?? given,
            };
        }

        var unproduced = new[]
            {
                (Parameters.IdTokenSignedResponseAlg, request.IdTokenSignedResponseAlg),
                (Parameters.AuthorizationSignedResponseAlg, request.AuthorizationSignedResponseAlg),
                (Parameters.UserInfoSignedResponseAlg, SecurityProfileConsistency.SignedOrNull(request.UserInfoSignedResponseAlg)),
                (Parameters.IntrospectionSignedResponseAlg,
                    SecurityProfileConsistency.SignedOrNull(request.IntrospectionSignedResponseAlg)),
            }
            .Where(setting => setting.Item2 is { } algorithm && !Produces(algorithm))
            .Select(setting => $"{setting.Item1} is {setting.Item2}, which no signing key of this server produces")
            .ToArray();

        if (unproduced.Length > 0)
            return ErrorFactory.InvalidClientMetadata(string.Join("; ", unproduced));

        context.Request = request;
        return null;
    }
}
