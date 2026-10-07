// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// Puts <see cref="SingleValueBinder"/> in front of the default binding of every simple value a model of this package
/// binds. A repeated parameter such as <c>resource</c> binds to an array and is left alone, and so is a value whose
/// own binder already refuses a repetition by failing to read it.
/// </summary>
internal sealed class SingleValueBinderProvider : IModelBinderProvider
{
    /// <inheritdoc />
    public IModelBinder? GetBinder(ModelBinderProviderContext context)
    {
        var metadata = context.Metadata;

        // Only the models this package generates, so a host's own controllers bind as they always have, and only a
        // value read from the query or the form: a header such as DPoP keeps the binding its own source gives it
        if (metadata.ContainerType?.Assembly != typeof(SingleValueBinderProvider).Assembly)
            return null;

        if (metadata.IsComplexType || metadata.IsEnumerableType || context.BindingInfo.BinderType is not null)
            return null;

        if (!ReadsQueryOrForm(context.BindingInfo.BindingSource))
            return null;

        var loggerFactory = context.Services.GetRequiredService<ILoggerFactory>();
        return new SingleValueBinder(new SimpleTypeModelBinder(metadata.ModelType, loggerFactory));
    }

    private static bool ReadsQueryOrForm(BindingSource? source)
        => source is null ||
           source.CanAcceptDataFrom(BindingSource.Query) ||
           source.CanAcceptDataFrom(BindingSource.Form);
}
