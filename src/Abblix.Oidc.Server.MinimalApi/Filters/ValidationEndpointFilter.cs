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
        var failures = new List<string>();
        foreach (var model in context.Arguments.OfType<IValidatableModel>())
            failures.AddRange(await FailuresOf(model));

        return failures.Count > 0
            ? ErrorFactory.InvalidRequest(failures).Format(StatusCodes.Status400BadRequest)
            : await next(context);
    }

    private static async Task<IEnumerable<string>> FailuresOf(IValidatableModel model)
    {
        if (model.FormUnreadable)
            return [ErrorFactory.UnreadableForm];

        // A refused parameter is left unbound, so validating the model would also report it missing, which says
        // nothing the refusal did not
        var refusals = model.RepeatedParameters.Select(ErrorFactory.RepeatedParameter)
            .Concat(model.MalformedParameters.Select(ErrorFactory.MalformedParameter))
            .ToArray();
        if (refusals.Length > 0)
            return refusals;

        var results = new List<ValidationResult>();
        await Validator.TryValidateObjectAsync(model, new ValidationContext(model), results, validateAllProperties: true);
        return results.Select(result => result.ErrorMessage ?? string.Empty);
    }
}
