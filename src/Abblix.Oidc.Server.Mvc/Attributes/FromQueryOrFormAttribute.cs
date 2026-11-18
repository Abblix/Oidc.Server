// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Abblix.Oidc.Server.Mvc.Attributes;

/// <summary>
/// Binds a model from the query string and the posted form together, for an endpoint a client may call with either
/// GET or POST, such as the authorization endpoint (OpenID Connect Core 1.0 section 3.1.2.1).
/// </summary>
/// <remarks>
/// <para>The model's parameters are read under their own names, never under a prefix naming the action parameter, so
/// <c>client_id</c> binds and <c>request.client_id</c> does not. The Minimal API host reads the same request through
/// <c>RequestValues</c>; the end-to-end scenarios compiled for both hosts send each request to both.</para>
/// <para>The order of the two sources here decides nothing: MVC asks the form before the query, as its value provider
/// factories are registered. A parameter that takes one value and arrives in both is refused as a repetition, while
/// the entries of one that may repeat, such as <c>resource</c>, are read from the form alone when the form carries
/// any.</para>
/// <para>On a model type it applies to every action parameter of that type.</para>
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Parameter)]
public class FromQueryOrFormAttribute : Attribute, IBindingSourceMetadata, IModelNameProvider
{
	private static readonly BindingSource QueryOrForm = CompositeBindingSource.Create(
		[BindingSource.Query, BindingSource.Form],
		nameof(FromQueryOrFormAttribute));

	/// <inheritdoc />
	public BindingSource BindingSource => QueryOrForm;

	/// <inheritdoc />
	public string Name => string.Empty;
}
