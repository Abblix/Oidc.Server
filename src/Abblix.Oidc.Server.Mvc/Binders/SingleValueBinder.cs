// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// Binds a parameter that takes one value, refusing it when the request carries it more than once.
/// </summary>
/// <remarks>
/// RFC 6749 section 3.1: "Request and response parameters MUST NOT be included more than once." The default binding
/// keeps the first value and drops the rest without a word, so a request saying two things at once would be served
/// as if it said one.
/// </remarks>
/// <param name="inner">The binding the parameter gets when it is sent once.</param>
internal sealed class SingleValueBinder(IModelBinder inner) : IModelBinder
{
    /// <inheritdoc />
    public Task BindModelAsync(ModelBindingContext bindingContext)
    {
        if (bindingContext.ValueProvider.GetValue(bindingContext.ModelName).Length > 1)
        {
            bindingContext.ModelState.TryAddModelError(bindingContext.ModelName, RepeatedMessage(bindingContext.ModelName));
            return Task.CompletedTask;
        }

        return inner.BindModelAsync(bindingContext);
    }

    /// <summary>
    /// What a request carrying <paramref name="name"/> more than once is told.
    /// </summary>
    public static string RepeatedMessage(string name) => $"The parameter '{name}' is included more than once";
}
