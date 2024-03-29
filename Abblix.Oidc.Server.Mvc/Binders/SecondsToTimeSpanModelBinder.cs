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

using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// A model binder that converts seconds (as string) to a <see cref="TimeSpan"/> object.
/// </summary>
/// <remarks>
/// This model binder is useful for binding API parameters that are provided as seconds in string format,
/// and need to be converted to a <see cref="TimeSpan"/> for internal processing.
/// </remarks>
public class SecondsToTimeSpanModelBinder : ModelBinderBase
{
    /// <summary>
    /// Attempts to parse the provided string value representing seconds into a <see cref="TimeSpan"/> object.
    /// </summary>
    /// <param name="type">The type of the model being bound. Expected to be <see cref="TimeSpan"/> or compatible.</param>
    /// <param name="values">The string values from the request, representing seconds.</param>
    /// <param name="result">The parsed <see cref="TimeSpan"/> object, if successful.</param>
    /// <returns>
    /// <c>true</c> if the parsing succeeds and a valid <see cref="TimeSpan"/> is created; otherwise, <c>false</c>.
    /// </returns>
    /// <remarks>
    /// This method parses the input string as a long, representing seconds, and converts it to a <see cref="TimeSpan"/>.
    /// If the input string is not a valid long or represents an invalid time duration, the parsing fails.
    /// </remarks>
    protected override bool TryParse(Type type, StringValues values, out object? result)
    {
        string? stringValue = values;
        if (stringValue == null)
        {
            result = null;
            return false;
        }

        result = TimeSpan.FromSeconds(long.Parse(stringValue));
        return true;
    }
}
