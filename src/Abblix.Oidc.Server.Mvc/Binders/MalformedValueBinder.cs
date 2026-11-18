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
/// Binds a request parameter as it would bind anyway, and names the parameter when its value cannot be read.
/// </summary>
/// <remarks>
/// A failure the binding records is a value it could not read, and the framework's message for it repeats the value
/// the client sent, which may hold characters RFC 6749 keeps out of error_description (sections 4.1.2.1, 4.2.2.1 and
/// 5.2); so the parameter is named instead, as the Minimal API host names it. A parameter that may repeat records the
/// failure under its name when sent plainly and under an indexed key such as <c>resource[0]</c> when sent with an
/// index, so the failures are looked for under every key the name starts.
/// </remarks>
/// <param name="inner">The binding the parameter gets anyway.</param>
internal sealed class MalformedValueBinder(IModelBinder inner) : IModelBinder
{
    /// <inheritdoc />
    public async Task BindModelAsync(ModelBindingContext bindingContext)
    {
        var name = bindingContext.ModelName;
        var modelState = bindingContext.ModelState;

        var failuresBefore = FailuresUnder(modelState, name);
        await inner.BindModelAsync(bindingContext);
        if (FailuresUnder(modelState, name) == failuresBefore)
            return;

        // Removed rather than emptied: the dictionary counts its errors apart from the entries and stops taking new
        // ones at its limit, so a request repeating a bad value up to it would otherwise leave no room for the name
        foreach (var key in modelState.FindKeysWithPrefix(name).Select(entry => entry.Key).ToList())
            modelState.Remove(key);

        modelState.TryAddModelError(name, ErrorFactory.MalformedParameter(name));
    }

    private static int FailuresUnder(ModelStateDictionary modelState, string name)
        => modelState.FindKeysWithPrefix(name).Sum(entry => entry.Value.Errors.Count);
}
