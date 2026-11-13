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
/// Binds a parameter a model splits by source - one member for its copy in the query, another for its copy in the
/// form - as <see cref="RequestParameterBinder"/> binds any other, but counting the parameter across both, so a request
/// sending it once in each is refused as a repetition, as it is when one member reads both.
/// </summary>
/// <param name="binderFactory">Builds the binding MVC gives the parameter's type.</param>
/// <param name="metadataProvider">Describes the parameter's type without the binder this property names.</param>
internal sealed class SplitSourceParameterBinder(
    IModelBinderFactory binderFactory,
    IModelMetadataProvider metadataProvider) : IModelBinder
{
    /// <inheritdoc />
    public Task BindModelAsync(ModelBindingContext bindingContext)
        => RequestParameterBinder.BindAsync(binderFactory, metadataProvider, bindingContext, acrossSplitSources: true);
}
