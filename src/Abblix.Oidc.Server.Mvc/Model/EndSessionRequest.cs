// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.ComponentModel.DataAnnotations;
using Abblix.Oidc.Server.Mvc.Attributes;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// The transport-bound counterpart of <see cref="Core.EndSessionRequest"/> for the RP-initiated
/// logout endpoint, reachable via GET and POST. The bound properties, model binders resolved from
/// the core wire-format markers and the projection back onto the core model are generated from
/// the core type; the cross-property validation below stays hand-written because it spans
/// several parameters at once.
/// </summary>
[GeneratedFrom(typeof(Core.EndSessionRequest), SupportsGet = true)]
public partial record EndSessionRequest : IValidatableObject
{
    /// <summary>
    /// Validates the end session request according to OIDC RP-Initiated Logout 1.0 specification.
    /// This method is called AFTER all properties are bound, ensuring cross-property validation works correctly.
    /// Per OIDC specification:
    /// - When post_logout_redirect_uri is used without id_token_hint, client_id identifies the client
    /// - When id_token_hint is provided, the OP can extract client identity from the token
    /// - When neither are provided, the OP uses session cookies to identify the user
    /// </summary>
    /// <param name="validationContext">The validation context.</param>
    /// <returns>A collection of validation results.</returns>
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (PostLogoutRedirectUri is not null &&
            string.IsNullOrWhiteSpace(IdTokenHint) &&
            string.IsNullOrWhiteSpace(ClientId))
        {
            yield return new ValidationResult(
                "The client_id field is required when post_logout_redirect_uri is specified without id_token_hint.",
                [nameof(ClientId)]);
        }
    }
}
