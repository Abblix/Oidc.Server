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

namespace Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;

/// <summary>
/// Represents an interface for creating a response to build the content of an OpenID Connect check-session frame (OP frame).
/// This interface defines a method for asynchronously processing the check session request and generating a response.
/// </summary>
public interface ICheckSessionHandler
{
	/// <summary>
	/// Asynchronously processes the check session request and generates a response containing the content of the OP check-session frame.
	/// </summary>
	/// <returns>A task representing the response, which includes the HTML content of the check-session frame.</returns>
	Task<CheckSessionResponse> HandleAsync();
}
