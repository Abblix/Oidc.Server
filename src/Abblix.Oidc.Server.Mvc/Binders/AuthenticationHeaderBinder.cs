// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.DeclarativeBinding;
using Abblix.Oidc.Server.Mvc.Attributes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// A model binder for binding authentication header values.
/// </summary>
/// <remarks>
/// This binder is specifically designed to extract and bind authentication header values from HTTP requests.
/// It extends the functionality of <see cref="ModelBinderBase"/> to handle authentication headers.
/// </remarks>
[Binds(typeof(AuthorizationHeaderAttribute))]
public class AuthenticationHeaderBinder : ModelBinderBase
{
    /// <summary>
    /// Asynchronously binds an authentication header model.
    /// </summary>
    /// <param name="bindingContext">The <see cref="ModelBindingContext"/> for the binding operation.</param>
    /// <remarks>
    /// The method extracts authentication header data from the request and tries to bind it to the model.
    /// </remarks>
    public override async Task BindModelAsync(ModelBindingContext bindingContext)
    {
        var headerValueProvider = new HeaderValueProvider(bindingContext.HttpContext.Request.Headers);

        var bindingInfo = BindingInfo.GetBindingInfo(
            bindingContext.ModelType.GetCustomAttributes(false),
            bindingContext.ModelMetadata);

        var childBindingContext = DefaultModelBindingContext.CreateBindingContext(
            bindingContext.ActionContext,
            headerValueProvider,
            bindingContext.ModelMetadata,
            bindingInfo,
            bindingContext.ModelName);

        await base.BindModelAsync(childBindingContext);

        bindingContext.Result = childBindingContext.Result;
    }

    /// <summary>
    /// Binds every line of the header field as received, never joined into one value.
    /// </summary>
    /// <remarks>
    /// RFC 9110 section 11.6.2 defines the field as <c>Authorization = credentials</c>, which is not a list, so the
    /// lines cannot be recombined (section 5.3): each is the credentials of a method of its own, and which of them a
    /// request may carry is the endpoint's question, not the binder's.
    /// </remarks>
    /// <param name="type">The type of the model to bind to.</param>
    /// <param name="values">The header field lines.</param>
    /// <param name="result">The lines as an array.</param>
    /// <returns>Always true: a line is kept whether or not it parses as credentials.</returns>
    protected override bool TryParse(Type type, StringValues values, out object? result)
    {
        result = values.ToArray();
        return true;
    }

    /// <summary>
    /// Provides values from HTTP headers.
    /// </summary>
    /// <param name="headers">The HTTP header dictionary to provide values from.</param>
    private sealed class HeaderValueProvider(IHeaderDictionary headers) : IValueProvider
    {
        /// <inheritdoc />
        public bool ContainsPrefix(string prefix)
            => headers.ContainsKey(prefix);

        /// <inheritdoc />
        public ValueProviderResult GetValue(string key)
            => headers.TryGetValue(key, out var values) ? new ValueProviderResult(values) : ValueProviderResult.None;
    }
}
