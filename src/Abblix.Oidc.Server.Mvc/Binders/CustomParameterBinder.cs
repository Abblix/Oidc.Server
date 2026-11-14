// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// Binds a query or form parameter of this package's request models that reads its value through a binder of its
/// own, such as a space-separated list, refusing it when it is sent more than once and naming it when its value cannot
/// be read.
/// </summary>
/// <remarks>
/// The model generator puts it on the property in place of <typeparamref name="TBinder"/>, since a property names one
/// model binder. The value such a binder reads is one value, however many items it lists, so it is always counted.
/// </remarks>
/// <typeparam name="TBinder">The binder that reads the parameter's value.</typeparam>
/// <param name="services">Creates <typeparamref name="TBinder"/> as MVC creates a binder a property names.</param>
internal sealed class CustomParameterBinder<TBinder>(IServiceProvider services) : IModelBinder
    where TBinder : IModelBinder
{
    /// <inheritdoc />
    public Task BindModelAsync(ModelBindingContext bindingContext)
        => new SingleValueBinder(new MalformedValueBinder(ActivatorUtilities.CreateInstance<TBinder>(services)))
            .BindModelAsync(bindingContext);
}
