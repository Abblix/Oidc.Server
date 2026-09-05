// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Defines the contract for a token context validator, responsible for validating different aspects of a token request
/// within a given context. Implementations of this interface ensure that the token request adheres to
/// the expected security and business rules.
/// </summary>
public interface ITokenContextValidator
{
    /// <summary>
    /// Asynchronously validates the token request within the provided context, checking for compliance with
    /// the necessary validation rules such as client authentication, scope validation, grant validation, etc.
    /// </summary>
    /// <param name="context">The context containing the token request and related information that needs to be validated.</param>
    /// <returns>
    /// A <see cref="OidcError"/> containing error details if the validation fails;
    /// otherwise, returns null indicating that the validation was successful.
    /// </returns>
    [Obsolete("Implement and call the overload taking a CancellationToken. This one is kept so an existing " +
              "implementation keeps working, and will be removed in the next major version.")]
    [SuppressMessage("Major Code Smell", "S1133:Deprecated code should be removed",
        Justification = "Removal is scheduled and tracked: the overload is kept only so a caller written against the pre-2.4 signature keeps working, and it goes in the next major version (#302).")]
    Task<OidcError?> ValidateAsync(TokenValidationContext context)
        => ValidateAsync(context, CancellationToken.None);

    /// <inheritdoc cref="ValidateAsync(TokenValidationContext)"/>
    /// <param name="context">The context containing the token request and related information.</param>
    /// <param name="cancellationToken">
    /// Abandons validation when the caller stops waiting. It is a parameter rather than a member of the
    /// context because the context carries per-call data, and a cancellation token is not data.
    /// </param>
    /// <remarks>
    /// This is the member an implementation provides. The obsolete overload above defaults to forwarding here,
    /// so a caller still holding the old signature keeps working, while an implementation that provided only
    /// the old one fails to compile rather than silently never receiving the token.
    /// </remarks>
    Task<OidcError?> ValidateAsync(TokenValidationContext context, CancellationToken cancellationToken);
}
