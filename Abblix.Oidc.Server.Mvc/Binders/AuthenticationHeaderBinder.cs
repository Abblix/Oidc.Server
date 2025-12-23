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

using System.Net.Http.Headers;
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
    /// Tries to parse the authentication header from the provided string values.
    /// </summary>
    /// <param name="type">The type of the model to bind to.</param>
    /// <param name="values">The header values to parse.</param>
    /// <param name="result">The resulting parsed object if successful.</param>
    /// <returns>True if parsing is successful, otherwise false.</returns>
    protected override bool TryParse(Type type, StringValues values, out object? result)
    {
        if (!AuthenticationHeaderValue.TryParse(values, out var headerValue))
        {
            result = null;
            return false;
        }

        result = headerValue;
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
