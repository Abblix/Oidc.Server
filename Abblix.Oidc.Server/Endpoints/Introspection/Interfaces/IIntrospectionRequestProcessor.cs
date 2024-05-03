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

namespace Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;

/// <summary>
/// Represents a contract for generating a document with metadata about an inspected token, including its active status.
/// </summary>
public interface IIntrospectionRequestProcessor
{
	/// <summary>
	/// Processes an introspection request and returns an IntrospectionResponse with token metadata.
	/// </summary>
	/// <param name="request">The ValidIntrospectionRequest containing the token to be inspected.</param>
	/// <returns>An IntrospectionResponse containing metadata about the token.</returns>
	Task<IntrospectionResponse> ProcessAsync(ValidIntrospectionRequest request);
}
