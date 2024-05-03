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
