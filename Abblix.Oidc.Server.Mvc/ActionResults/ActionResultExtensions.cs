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

using Microsoft.AspNetCore.Mvc;
using CookieOptions = Microsoft.AspNetCore.Http.CookieOptions;

namespace Abblix.Oidc.Server.Mvc.ActionResults;

public static class ActionResultExtensions
{
	/// <summary>
	/// Decorates an <see cref="ActionResult"/> to append a cookie to the response.
	/// </summary>
	/// <param name="innerResult">The <see cref="ActionResult"/> to decorate.</param>
	/// <param name="name">The name of the cookie to append.</param>
	/// <param name="value">The value of the cookie.</param>
	/// <param name="options">The <see cref="CookieOptions"/> to configure the cookie.</param>
	/// <returns>A decorated <see cref="ActionResult"/> that appends the specified cookie.</returns>
	public static ActionResult WithAppendCookie(this ActionResult innerResult, string name, string value, CookieOptions options)
		=> new ActionResultDecorator(innerResult, response => response.Cookies.Append(name, value, options));

	/// <summary>
	/// Decorates an <see cref="ActionResult"/> to delete a cookie from the response.
	/// </summary>
	/// <param name="innerResult">The <see cref="ActionResult"/> to decorate.</param>
	/// <param name="name">The name of the cookie to delete.</param>
	/// <param name="options">The <see cref="CookieOptions"/> to configure the deletion of the cookie.</param>
	/// <returns>A decorated <see cref="ActionResult"/> that deletes the specified cookie.</returns>
	public static ActionResult WithDeleteCookie(this ActionResult innerResult, string name, CookieOptions options)
		=> new ActionResultDecorator(innerResult, response => response.Cookies.Delete(name, options));
}
