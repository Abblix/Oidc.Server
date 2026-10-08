// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Common.Validation;

/// <summary>
/// Builds <see cref="OidcError"/> instances for the request-binding layer shared by every endpoint and both transport
/// adapters. The counterpart of the per-area error factories (authorization validation, token grants, dynamic client
/// registration, ...): those cover protocol-specific failures, this covers the malformed-request failures the
/// declarative model validation surfaces before any handler runs. It sits in its own <c>Common.Validation</c>
/// namespace rather than bare <c>Common</c> so it does not collide with those per-area <c>ErrorFactory</c> classes in
/// the many core files that import <c>Common</c>.
/// </summary>
public static class ErrorFactory
{
    private const string FallbackDescription =
        "The request is missing a required parameter, includes an invalid parameter value, " +
        "includes a parameter more than once, or is otherwise malformed";

    /// <summary>
    /// The validation message for a parameter that takes one value and was sent more than once, which RFC 6749
    /// sections 3.1 and 3.2 forbid: "Request and response parameters MUST NOT be included more than once."
    /// </summary>
    /// <param name="name">The parameter's name as sent.</param>
    public static string RepeatedParameter(string name) => $"The parameter '{name}' is included more than once";

    /// <summary>
    /// The validation message for a parameter whose value cannot be read as the type it carries.
    /// </summary>
    /// <param name="name">The parameter's name as sent.</param>
    public static string MalformedParameter(string name) => $"The parameter '{name}' has a value that cannot be read";

    /// <summary>
    /// The validation message for a request whose form body cannot be read, such as one past the form limits.
    /// </summary>
    public const string UnreadableForm = "The request body cannot be read as a form";

    /// <summary>
    /// Maps a flat sequence of model-validation messages onto an <see cref="OidcError"/> carrying the
    /// <see cref="ErrorCodes.InvalidRequest"/> code. The input is a plain message sequence on purpose, so each
    /// transport adapter can feed it the output of
    /// <see cref="System.ComponentModel.DataAnnotations.Validator"/> and share one source of truth for
    /// "a malformed request becomes invalid_request".
    /// </summary>
    /// <param name="messages">The human-readable validation messages collected for the rejected request.</param>
    /// <returns>An <see cref="OidcError"/> describing the failure in OAuth terms.</returns>
    public static OidcError InvalidRequest(IEnumerable<string> messages)
    {
        var description = string.Join(' ', messages.Where(message => !string.IsNullOrWhiteSpace(message)));

        // error_description is optional per RFC 6749 section 5.2, so an empty join means the caller had no concrete
        // message and the generic fallback stands in for it.
        return new OidcError(
            ErrorCodes.InvalidRequest,
            description.Length > 0 ? description : FallbackDescription);
    }
}
