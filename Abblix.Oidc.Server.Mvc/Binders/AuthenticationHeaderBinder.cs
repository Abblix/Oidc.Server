// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
    private class HeaderValueProvider : IValueProvider
    {
        private readonly IHeaderDictionary _headers;

        /// <summary>
        /// Initializes a new instance of the <see cref="HeaderValueProvider"/> class.
        /// </summary>
        /// <param name="headers">The HTTP header dictionary to provide values from.</param>
        public HeaderValueProvider(IHeaderDictionary headers)
        {
            _headers = headers;
        }

        /// <inheritdoc />
        public bool ContainsPrefix(string prefix)
            => _headers.ContainsKey(prefix);

        /// <inheritdoc />
        public ValueProviderResult GetValue(string key)
            => _headers.TryGetValue(key, out var values) ? new ValueProviderResult(values) : ValueProviderResult.None;
    }
}
