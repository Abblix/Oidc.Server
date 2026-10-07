// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Validation;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// Binds a parameter that takes one value, refusing it when the request carries it more than once.
/// </summary>
/// <remarks>
/// RFC 6749 sections 3.1 and 3.2: "Request and response parameters MUST NOT be included more than once." The default
/// binding keeps one value and drops the rest without a word, so a request saying two things at once would be served
/// as if it said one. The count is taken from the query and the form together, because the value providers answer
/// with the first source that has the name, and a value sent once in each would otherwise read as sent once.
/// </remarks>
/// <param name="inner">The binding the parameter gets when it is sent once.</param>
internal sealed class SingleValueBinder(IModelBinder inner) : IModelBinder
{
    /// <inheritdoc />
    public Task BindModelAsync(ModelBindingContext bindingContext)
    {
        var name = bindingContext.ModelName;
        var request = bindingContext.HttpContext.Request;
        var count = request.Query[name].Count + (request.HasFormContentType ? request.Form[name].Count : 0);
        if (count > 1)
        {
            bindingContext.ModelState.TryAddModelError(name, ErrorFactory.RepeatedParameter(name));
            return Task.CompletedTask;
        }

        return inner.BindModelAsync(bindingContext);
    }
}
