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
/// as if it said one. The count covers the sources the endpoint reads, taken from the value providers MVC already
/// narrowed to the action's binding source: the query and the form for an endpoint reading both, so a value sent once
/// in each counts twice, and the form alone for one reading the body, so a copy in the query, never read, is not
/// counted. Each source is asked once, because the composite answers with its first provider holding the name and so
/// does not count a value twice through the provider that mirrors it.
/// </remarks>
/// <param name="inner">The binding the parameter gets when it is sent once.</param>
internal sealed class SingleValueBinder(IModelBinder inner) : IModelBinder
{
    /// <inheritdoc />
    public async Task BindModelAsync(ModelBindingContext bindingContext)
    {
        var name = bindingContext.ModelName;
        var sources = (IBindingSourceValueProvider)bindingContext.ValueProvider;
        if (CountIn(sources, BindingSource.Query, name) + CountIn(sources, BindingSource.Form, name) > 1)
        {
            bindingContext.ModelState.TryAddModelError(name, ErrorFactory.RepeatedParameter(name));
            return;
        }

        var failuresBefore = FailuresOn(bindingContext.ModelState, name);
        await inner.BindModelAsync(bindingContext);

        // A failure the binding records is a value it could not read, and the framework's message for it repeats
        // the value the client sent, which may hold characters RFC 6749 keeps out of error_description; so the
        // parameter is named instead, as the Minimal API host names it
        if (FailuresOn(bindingContext.ModelState, name) > failuresBefore)
        {
            bindingContext.ModelState[name]!.Errors.Clear();
            bindingContext.ModelState.TryAddModelError(name, ErrorFactory.MalformedParameter(name));
        }
    }

    private static int FailuresOn(ModelStateDictionary state, string name)
        => state.TryGetValue(name, out var entry) ? entry.Errors.Count : 0;

    private static int CountIn(IBindingSourceValueProvider sources, BindingSource source, string name)
        => sources.Filter(source)?.GetValue(name).Length ?? 0;
}
