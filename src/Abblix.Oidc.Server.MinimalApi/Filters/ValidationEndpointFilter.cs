// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.ComponentModel.DataAnnotations;
using Abblix.Oidc.Server.Common.Validation;
using Abblix.Oidc.Server.MinimalApi.Model;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Filters;

/// <summary>
/// A group-scoped endpoint filter that runs the declarative validation rules carried by the bound request models
/// (those marked <see cref="IValidatableModel"/>) before the handler runs, short-circuiting a violation to the OAuth
/// <c>invalid_request</c> response. The Minimal API counterpart of the MVC adapter's <c>ReturnsOidcInvalidRequest</c>
/// controller filter; being attached to the OIDC route group, it confines the OAuth shaping to these endpoints and a
/// host cannot clobber it the way it could a global option.
/// </summary>
internal sealed class ValidationEndpointFilter : IEndpointFilter
{
    /// <inheritdoc />
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        List<ValidationResult>? failures = null;
        foreach (var argument in context.Arguments)
        {
            if (argument is not IValidatableModel)
                continue;

            var results = new List<ValidationResult>();
            if (!Validator.TryValidateObject(argument, new ValidationContext(argument), results, validateAllProperties: true))
                (failures ??= []).AddRange(results);
        }

        return failures is { Count: > 0 }
            ? ErrorFactory
                .InvalidRequest(failures.Select(result => result.ErrorMessage ?? string.Empty))
                .Format(StatusCodes.Status400BadRequest)
            : await next(context);
    }
}
