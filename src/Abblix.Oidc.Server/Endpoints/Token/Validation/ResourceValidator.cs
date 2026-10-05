// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ResourceIndicators;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Provides validation for resource-related data within token requests, ensuring that all requested resources are
/// recognized and appropriately scoped according to OAuth 2.0 and OpenID Connect standards.
/// </summary>
/// <param name="resourceManager">The manager responsible for validating and managing resource definitions.</param>
/// <param name="inference">Infers the resource a request naming none is for from its scopes.</param>
public class ResourceValidator(IResourceManager resourceManager, ResourceInference inference)
    : SyncTokenContextValidatorBase
{
    /// <summary>
    /// The grants whose audience an authorization made earlier settled: the request may narrow it, and nothing is
    /// inferred for it.
    /// </summary>
    private static readonly HashSet<string> AuthorizedEarlier = new(StringComparer.Ordinal)
    {
        GrantTypes.AuthorizationCode,
        GrantTypes.RefreshToken,
        GrantTypes.DeviceAuthorization,
        GrantTypes.Ciba,
    };

    /// <summary>
    /// Validates the resources specified in a token request against known resource definitions.
    /// This validation ensures that only registered and approved resources are accessed by the client.
    /// </summary>
    /// <param name="context">The context of the token validation including the request and client information.</param>
    /// <returns>
    /// A <see cref="OidcError"/> if the validation fails, indicating the nature of the error and providing
    /// an error message; otherwise, null if the resource validation passes successfully.
    /// </returns>
    protected override OidcError? Validate(TokenValidationContext context)
    {
        var request = context.Request;

        if (request.Resources is not { Length: > 0 } && !AuthorizedEarlier.Contains(request.GrantType))
        {
            if (!inference.TryInfer(request.Scope, out var inferred, out var ambiguity))
                return new OidcError(ErrorCodes.InvalidScope, ambiguity);

            // A grant the request itself authorizes builds its audience from the request, so the inferred
            // resource is put where a named one would be
            if (inferred is not null)
                request.Resources = [inferred];
        }

        if (request.Resources is not { Length: > 0 })
            return null;

        if (!resourceManager.Validate(
                request.Resources,
                request.Scope,
                out var resources,
                out var errorDescription))
        {
            return new OidcError(ErrorCodes.InvalidTarget, errorDescription);
        }

        context.Resources = resources;
        return null;
    }
}
