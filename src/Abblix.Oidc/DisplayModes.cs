// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Oidc;

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
