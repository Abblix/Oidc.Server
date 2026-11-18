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
/// Names the model binder of a request parameter of this package's models and leaves its binding source to the
/// action, so the parameter is still described as a form or query field.
/// </summary>
/// <remarks>
/// <see cref="Microsoft.AspNetCore.Mvc.ModelBinderAttribute"/> names a binder too, but reports its source as custom,
/// and a host that describes its API, these endpoints included, would then lose where each parameter is sent.
/// </remarks>
/// <param name="binderType">The model binder of the parameter.</param>
[AttributeUsage(AttributeTargets.Property)]
internal sealed class ParameterBinderAttribute(Type binderType) : Attribute, IBinderTypeProviderMetadata
{
    /// <inheritdoc />
    public Type BinderType => binderType;

    /// <inheritdoc />
    public BindingSource? BindingSource => null;
}
