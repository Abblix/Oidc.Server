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
