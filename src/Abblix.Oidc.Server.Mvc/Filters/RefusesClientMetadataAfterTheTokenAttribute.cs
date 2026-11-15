// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Mime;
using Abblix.Oidc.Server.Common.Validation;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Refuses a client registration or update whose body cannot be read, by its token first: the body's own refusal - a
/// media type other than JSON (415), a body over the bound (413), metadata that does not read (400
/// <c>invalid_client_metadata</c>) - is answered only to a request whose token passes. The registration endpoint
/// requiring an initial access token (RFC 7591 section 3) and the client configuration endpoint (RFC 7592 section 2.2,
/// which answers a token "not valid" as RFC 6750 does) are protected resources, and RFC 6750 section 3 has a request
/// without a token enabling access answered with the WWW-Authenticate field, whatever its body holds.
/// </summary>
/// <remarks>
/// Takes the place of <see cref="ConsumesAttribute"/>, whose 415 routing answers before any filter runs, and declares
/// the same media type to the API description.
/// </remarks>
[AttributeUsage(AttributeTargets.Method)]
internal abstract class RefusesClientMetadataAfterTheTokenAttribute
	: Attribute, IAsyncActionFilter, IOrderedFilter, IApiRequestMetadataProvider
{
	// Ahead of the framework's filter answering an unsupported content type (order -3000), so the token comes first
	// for that refusal too
	private const int OrderBeforeUnsupportedContentType = -3001;

	private static readonly MediaType Json = new(MediaTypeNames.Application.Json);

	/// <inheritdoc />
	public int Order => OrderBeforeUnsupportedContentType;

	/// <inheritdoc />
	public void SetContentTypes(MediaTypeCollection contentTypes)
	{
		contentTypes.Clear();
		contentTypes.Add(MediaTypeNames.Application.Json);
	}

	/// <summary>
	/// Whether the request declares the one media type the client metadata is read in, as <see cref="ConsumesAttribute"/>
	/// decides it.
	/// </summary>
	public static bool DeclaresJson(HttpRequest request)
		=> request.ContentType is { } contentType && new MediaType(contentType).IsSubsetOf(Json);

	/// <inheritdoc />
	public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
	{
		if (BodyRefusal(context) is not { } refusal)
		{
			await next();
			return;
		}

		context.Result = await RefuseByTheTokenAsync(context) ?? refusal;
	}

	/// <summary>
	/// The answer to the request's token where the token does not pass, or <c>null</c> where it does or the endpoint
	/// asks for none.
	/// </summary>
	protected abstract Task<ActionResult?> RefuseByTheTokenAsync(ActionExecutingContext context);

	private static ActionResult? BodyRefusal(ActionExecutingContext context)
	{
		// A refusal decided before the body was bound, such as a body over the bound
		if (context.HttpContext.Features.Get<ClientMetadataRefusal>() is { Result: var recorded })
			return recorded;

		if (!DeclaresJson(context.HttpContext.Request))
			return new UnsupportedMediaTypeResult();

		var body = context.ActionDescriptor.Parameters
			.Single(parameter => parameter.BindingInfo?.BindingSource == BindingSource.Body);

		if (context.ActionArguments.TryGetValue(body.Name, out var value) && value is not null)
			return null;

		// A character set the JSON reader cannot decode is reported as an unsupported content type, as the framework
		// answers it
		var unsupported = context.ModelState.Values
			.SelectMany(entry => entry.Errors)
			.Any(error => error.Exception is UnsupportedContentTypeException);

		return unsupported
			? new UnsupportedMediaTypeResult()
			: ErrorFactory.UnreadableClientMetadata.Format(StatusCodes.Status400BadRequest);
	}
}
