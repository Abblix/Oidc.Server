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
/// Names the model binder of a request header a model of this package reads through a binder of its own, and
/// describes the property as that header.
/// </summary>
/// <remarks>
/// <see cref="Microsoft.AspNetCore.Mvc.ModelBinderAttribute"/> would name the binder too, but report its source as
/// custom, and a host that describes its API, these endpoints included, would lose that the value is a header.
/// </remarks>
/// <param name="binderType">The model binder that reads the header.</param>
/// <param name="name">The header's name.</param>
[AttributeUsage(AttributeTargets.Property)]
internal sealed class HeaderBinderAttribute(Type binderType, string name)
    : Attribute, IBinderTypeProviderMetadata, IModelNameProvider
{
    /// <inheritdoc />
    public Type BinderType => binderType;

    /// <inheritdoc />
    public BindingSource BindingSource => BindingSource.Header;

    /// <inheritdoc />
    public string Name => name;
}
