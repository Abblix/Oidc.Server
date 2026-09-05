// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
