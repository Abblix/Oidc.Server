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

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// The class representing the display modes for the authentication and consent UI.
/// </summary>
public static class DisplayModes
{
	/// <summary>
	/// The Authorization Server SHOULD display the authentication and consent UI consistent with a full User Agent page view.
	/// If the display parameter is not specified, this is the default display mode.
	/// </summary>
	public const string Page = "page";

	/// <summary>
	/// The Authorization Server SHOULD display the authentication and consent UI consistent with a popup User Agent window.
	/// The popup User Agent window should be of an appropriate size for a login-focused dialog and should not obscure
	/// the entire window that it is popping up over.
	/// </summary>
	public const string Popup = "popup";

	/// <summary>
	/// The Authorization Server SHOULD display the authentication and consent UI consistent with a device that leverages a touch interface.
	/// </summary>
	public const string Touch = "touch";

	/// <summary>
	/// The Authorization Server SHOULD display the authentication and consent UI consistent with a "feature phone" type display.
	/// </summary>
	public const string Wap = "wap";
}
