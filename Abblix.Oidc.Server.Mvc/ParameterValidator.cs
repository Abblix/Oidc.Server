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

using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Provides functionality for validating parameters, emulating the behavior of ASP.NET MVC's
/// <see cref="RequiredAttribute"/>. This class implements the <see cref="IParameterValidator"/> interface to offer
/// standard parameter validation routines, enabling its use in core application code where model binding and MVC
/// validation attributes are not directly applicable.
/// </summary>
/// <remarks>
/// Use this class to enforce parameter requirements in service layers, domain models, or other parts of the application
/// where you want to ensure that inputs are not null without relying on MVC's model binding. This is especially useful
/// in scenarios where data validation needs to occur outside of web controllers, ensuring consistency in validation
/// logic across different layers of an application.
/// </remarks>
public class ParameterValidator : IParameterValidator
{
    /// <summary>
    /// Validates that a parameter is not null, emulating the enforcement of the <see cref="RequiredAttribute"/> in
    /// ASP.NET MVC. This method provides a straightforward way to ensure parameters meet their required conditions,
    /// throwing a descriptive exception if they are found to be null.
    /// </summary>
    /// <typeparam name="T">The type of the parameter to validate.</typeparam>
    /// <param name="value">The parameter value to validate. The method checks if this value is null.</param>
    /// <param name="name">The name of the parameter, which is used in constructing the exception message if
    /// the parameter is found to be null. This enhances the debuggability by specifying which parameter failed
    /// validation.</param>
    /// <exception cref="ArgumentNullException">Thrown if the parameter value is null, indicating that a required
    /// parameter was not provided.</exception>
    /// <remarks>
    /// This method simplifies the task of validating mandatory method parameters, ensuring that null values are
    /// caught early in the execution flow. By leveraging this method, developers can avoid repetitive null checks
    /// and focus on the core logic of their methods.
    /// </remarks>
    public void Required<T>([NotNull] T? value, string name) where T : class => value.Required(name);
}
