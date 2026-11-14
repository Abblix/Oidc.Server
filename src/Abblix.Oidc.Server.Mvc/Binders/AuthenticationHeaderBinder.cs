// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.DeclarativeBinding;
using Abblix.Oidc.Server.Mvc.Attributes;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// A model binder for binding authentication header values.
/// </summary>
/// <remarks>
/// This binder is specifically designed to extract and bind authentication header values from HTTP requests.
/// It extends the functionality of <see cref="ModelBinderBase"/> to handle authentication headers.
/// </remarks>
[Binds(typeof(AuthorizationHeaderAttribute))]
public class AuthenticationHeaderBinder : ModelBinderBase
{
    /// <summary>
    /// Binds every line of the header the model is named after, an empty line included.
    /// </summary>
    /// <param name="bindingContext">The <see cref="ModelBindingContext"/> for the binding operation.</param>
    /// <remarks>
    /// Reads the request's headers itself rather than through <see cref="ModelBinderBase.BindModelAsync"/>, which
    /// treats a parameter whose first value is empty as omitted (RFC 6749 section 3.1). That rule is about a parameter
    /// sent without a value; an empty Authorization line is still a line, and skipping it would drop the lines behind
    /// it, so a request repeating the field would read as carrying it once or not at all.
    /// </remarks>
    public override Task BindModelAsync(ModelBindingContext bindingContext)
    {
        if (bindingContext.HttpContext.Request.Headers.TryGetValue(bindingContext.ModelName, out var values) &&
            values.Count > 0)
        {
            bindingContext.Result = TryParse(bindingContext.ModelType, values, out var lines)
                ? ModelBindingResult.Success(lines)
                : ModelBindingResult.Failed();
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Binds every line of the header field as received, never joined into one value.
    /// </summary>
    /// <remarks>
    /// RFC 9110 section 11.6.2 defines the field as <c>Authorization = credentials</c>, which is not a list, so the
    /// lines cannot be recombined (section 5.3): each is the credentials of a method of its own, and which of them a
    /// request may carry is the endpoint's question, not the binder's.
    /// </remarks>
    /// <param name="type">The type of the model to bind to.</param>
    /// <param name="values">The header field lines.</param>
    /// <param name="result">The lines as an array.</param>
    /// <returns>Always true: a line is kept whether or not it parses as credentials.</returns>
    protected override bool TryParse(Type type, StringValues values, out object? result)
    {
        result = values.ToArray();
        return true;
    }
}
