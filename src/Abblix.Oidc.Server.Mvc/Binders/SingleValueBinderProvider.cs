// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// Puts <see cref="SingleValueBinder"/> in front of the binding every request parameter of this package's models
/// would get anyway, for each parameter that takes one value.
/// </summary>
/// <remarks>
/// A request parameter is a property the model generator marks with <see cref="BindPropertyAttribute"/>, which it
/// writes for the query and form parameters only: a header such as DPoP or Authorization, the client certificate and
/// a route value bind exactly as they would without this package. A parameter that may repeat, such as
/// <c>resource</c> or <c>audience</c>, binds to an array with no binder of its own and is left alone, while an array
/// with a binder of its own, such as <c>ui_locales</c>, is one value listing several items and is wrapped. A host's
/// own controllers bind exactly as they would without this package.
/// </remarks>
internal sealed class SingleValueBinderProvider : IModelBinderProvider
{
    /// <inheritdoc />
    public IModelBinder? GetBinder(ModelBinderProviderContext context)
    {
        var metadata = context.Metadata;
        if (metadata.ContainerType?.Assembly != typeof(SingleValueBinderProvider).Assembly)
            return null;

        if (metadata.ContainerType.GetProperty(metadata.PropertyName!)?.IsDefined(typeof(BindPropertyAttribute)) != true)
            return null;

        if (context.BindingInfo.BinderType is null && metadata.IsComplexType)
            return null;

        var inner = context.Services.GetRequiredService<IOptions<MvcOptions>>().Value.ModelBinderProviders
            .Where(provider => provider != this)
            .Select(provider => provider.GetBinder(context))
            .FirstOrDefault(binder => binder is not null);

        return inner is null ? null : new SingleValueBinder(inner);
    }
}
