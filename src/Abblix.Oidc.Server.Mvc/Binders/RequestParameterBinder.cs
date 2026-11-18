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
/// Binds a query or form parameter of this package's request models through the binding MVC gives its type, refusing
/// a parameter that takes one value when it is sent more than once and naming a parameter whose value cannot be read.
/// </summary>
/// <remarks>
/// The model generator puts it on each such property as its model binder, so it reaches this package's models and
/// nothing else in the host. A parameter that may repeat, such as <c>resource</c>, binds to a type MVC treats as
/// complex and is not counted; every other is.
/// </remarks>
/// <param name="binderFactory">Builds the binding MVC gives the parameter's type.</param>
/// <param name="metadataProvider">Describes the parameter's type without the binder this property names.</param>
internal sealed class RequestParameterBinder(IModelBinderFactory binderFactory, IModelMetadataProvider metadataProvider)
    : IModelBinder
{
    /// <inheritdoc />
    public Task BindModelAsync(ModelBindingContext bindingContext)
        => BindAsync(binderFactory, metadataProvider, bindingContext, acrossSplitSources: false);

    /// <summary>
    /// The binding both this binder and <see cref="SplitSourceParameterBinder"/> give a parameter, differing only in
    /// which sources the refusal of a repetition counts.
    /// </summary>
    internal static Task BindAsync(
        IModelBinderFactory binderFactory,
        IModelMetadataProvider metadataProvider,
        ModelBindingContext bindingContext,
        bool acrossSplitSources)
    {
        // Built from the type's metadata, not the property's: the property names this binder, and the factory would
        // hand it back. Cached per property, so the framework builds it once
        var inner = binderFactory.CreateBinder(new ModelBinderFactoryContext
        {
            Metadata = metadataProvider.GetMetadataForType(bindingContext.ModelType),
            BindingInfo = new BindingInfo(),
            CacheToken = bindingContext.ModelMetadata,
        });

        IModelBinder named = new MalformedValueBinder(inner);
        var binder = bindingContext.ModelMetadata.IsComplexType ? named : new SingleValueBinder(named, acrossSplitSources);
        return binder.BindModelAsync(bindingContext);
    }
}
