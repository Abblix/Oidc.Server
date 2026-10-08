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
        var models = context.Arguments.OfType<IValidatableModel>().ToArray();

        // The form belongs to the request, and every model bound from it records that it could not be read
        if (models.Any(model => model.FormUnreadable))
            return Refuse([ErrorFactory.UnreadableForm]);

        var failures = new List<string>();
        foreach (var model in models)
            failures.AddRange(await FailuresOf(model));

        // Two models of one request may bind the same parameter, such as client_id, and refuse it alike
        return failures.Count > 0 ? Refuse(failures.Distinct()) : await next(context);
    }

    private static IResult Refuse(IEnumerable<string> failures)
        => ErrorFactory.InvalidRequest(failures).Format(StatusCodes.Status400BadRequest);

    private static async Task<IEnumerable<string>> FailuresOf(IValidatableModel model)
    {
        var refusals = model.RepeatedParameters.Select(ErrorFactory.RepeatedParameter)
            .Concat(model.MalformedParameters.Select(ErrorFactory.MalformedParameter));

        // A refused parameter is left unbound, so validating it would also report it missing, which says nothing the
        // refusal did not; every other parameter is validated as usual
        var refused = model.RepeatedParameters.Concat(model.MalformedParameters).Select(model.MemberOf).ToHashSet();
        var results = new List<ValidationResult>();
        await Validator.TryValidateObjectAsync(model, new ValidationContext(model), results, validateAllProperties: true);

        return refusals.Concat(results
            .Where(result => !result.MemberNames.Any(refused.Contains))
            .Select(result => result.ErrorMessage ?? string.Empty));
    }
}
