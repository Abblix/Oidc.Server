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

using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Binders;

/// <summary>
/// Runs a model binder against a value the way MVC does, and reports what it decided.
/// </summary>
/// <remarks>
/// These binders are reached only through model binding, and their refusal paths are reached only by values
/// HTTP cannot express through a route: a parameter that arrives more than once, so the request carries two
/// values where the model wants one. Driving them from an end-to-end request was tried and does not work - the
/// request is answered before the binder sees such a value, which the coverage showed while the test passed.
/// So they are driven here directly, which is also the only way to observe what the binder decided rather than
/// what the endpoint eventually answered.
/// </remarks>
internal static class ModelBinderRunner
{
    /// <summary>What the binder decided: whether it produced a model, and what it produced.</summary>
    internal sealed record Outcome(bool IsModelSet, object? Model, ModelStateDictionary ModelState);

    internal static async Task<Outcome> BindAsync(IModelBinder binder, Type modelType, params string[] values)
    {
        var metadata = new EmptyModelMetadataProvider().GetMetadataForType(modelType);

        var context = new DefaultModelBindingContext
        {
            ActionContext = new ActionContext(new DefaultHttpContext(), new RouteData(), new ActionDescriptor()),
            ModelMetadata = metadata,
            ModelName = "value",
            ModelState = new ModelStateDictionary(),
            ValueProvider = new SingleEntryValueProvider("value", values),
        };

        await binder.BindModelAsync(context);

        return new Outcome(context.Result.IsModelSet, context.Result.Model, context.ModelState);
    }

    /// <summary>
    /// Runs a binder that reads the request's headers rather than the value provider - which
    /// <see cref="Abblix.Oidc.Server.Mvc.Binders.AuthenticationHeaderBinder"/> does, building its own provider
    /// over <c>Request.Headers</c>. Feeding it through the value provider instead leaves it with nothing to
    /// bind, so a test written that way reports a refusal it never exercised.
    /// </summary>
    internal static async Task<Outcome> BindHeaderAsync(
        IModelBinder binder, Type modelType, string headerName, string headerValue)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers[headerName] = headerValue;

        var context = new DefaultModelBindingContext
        {
            ActionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor()),
            ModelMetadata = new EmptyModelMetadataProvider().GetMetadataForType(modelType),
            ModelName = headerName,
            ModelState = new ModelStateDictionary(),
            ValueProvider = new SingleEntryValueProvider(headerName, []),
        };

        await binder.BindModelAsync(context);

        return new Outcome(context.Result.IsModelSet, context.Result.Model, context.ModelState);
    }

    /// <summary>
    /// A value provider holding one name and however many values were handed to it - including none, and
    /// including more than one, which is the shape the binders' refusal paths exist for.
    /// </summary>
    private sealed class SingleEntryValueProvider(string name, string[] values) : IValueProvider
    {
        public bool ContainsPrefix(string prefix) => prefix == name;

        public ValueProviderResult GetValue(string key)
            => key == name
                ? new ValueProviderResult(new StringValues(values), CultureInfo.InvariantCulture)
                : ValueProviderResult.None;
    }
}
