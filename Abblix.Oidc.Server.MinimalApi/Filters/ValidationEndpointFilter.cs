// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
