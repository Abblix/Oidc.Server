// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Mime;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Refuses a request body larger than <see cref="OidcOptions.MaxRegistrationRequestSize"/>, and one of a media type
/// other than JSON, before either is read.
/// </summary>
/// <remarks>
/// A resource filter because it is the last stage that still runs ahead of model binding. The registration and
/// update endpoints parse a foreign document and keep the members they do not model, which costs several times
/// the body's own size in memory, and binding runs before every validator - including the initial access token
/// check and the registration access token check. Expressed anywhere later, the bound would be paid for after
/// the allocation it exists to prevent, and an anonymous caller would be the one spending it.
/// <para>
/// The bound is enforced here rather than handed to the server, unlike the minimal API adapter, which
/// publishes it as endpoint metadata. The trade is deliberate and runs both ways: this holds on any server,
/// including one that does not implement <c>IHttpMaxRequestBodySizeFeature</c>, and it produces a normal 413
/// result instead of an exception thrown mid-action - but it buffers the body in managed memory to do so,
/// where the metadata route costs nothing. A declared length over the limit is refused without reading
/// anything, so only a body that hides its length behind chunked encoding is ever buffered.
/// </para>
/// </remarks>
[AttributeUsage(AttributeTargets.Method)]
internal sealed class LimitsRegistrationRequestSizeAttribute : Attribute, IAsyncResourceFilter, IOrderedFilter
{
	/// <summary>
	/// Stated rather than left to the default, so its place among the resource filters of the same scope does not fall
	/// through to the order reflection happens to return attributes in, which is not guaranteed.
	/// </summary>
	public int Order => 1;

	private static readonly MediaType Json = new(MediaTypeNames.Application.Json);

	/// <inheritdoc />
	public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
	{
		var request = context.HttpContext.Request;

		// The metadata is read in JSON alone, and a body declaring another media type or none is answered 415 without
		// reading a byte: an input formatter of the framework takes text/json too, and binding would parse such a body,
		// up to the server's own limit and past this bound, ahead of the token
		if (!DeclaresJson(request))
		{
			await RefuseAsync(context, next, new UnsupportedMediaTypeResult());
			return;
		}

		var limit = context.HttpContext.RequestServices
			.GetRequiredService<IOptions<OidcOptions>>().Value.MaxRegistrationRequestSize;

		// A cleared option means the deployment bounds the body elsewhere - at the server, or at a reverse
		// proxy in front of it - and asked us not to add one of our own.
		if (limit is not { } maxBytes)
		{
			await next();
			return;
		}

		// A declared length over the limit settles it without reading anything. It is the client's claim
		// rather than a measurement, so it can only be trusted in this direction: a claim of being too large
		// is not one anybody makes to get further in.
		if (request.ContentLength > maxBytes)
		{
			await RefuseAsync(context, next, new StatusOnlyResult(StatusCodes.Status413PayloadTooLarge));
			return;
		}

		// Reading one byte past the limit is what distinguishes "exactly at the limit" from "over it", and
		// reading is the only way to ask when no length was declared: a chunked body still arrives, and its
		// size is knowable only by taking it.
		var buffer = new MemoryStream();
		context.HttpContext.Response.RegisterForDispose(buffer);

		var copied = await CopyAtMostAsync(request.Body, buffer, maxBytes + 1, context.HttpContext.RequestAborted);
		if (copied > maxBytes)
		{
			await RefuseAsync(context, next, new StatusOnlyResult(StatusCodes.Status413PayloadTooLarge));
			return;
		}

		// Binding reads the body next, and this one has already been drained.
		buffer.Position = 0;
		request.Body = buffer;
		request.ContentLength = copied;

		await next();
	}

	/// <summary>
	/// Whether the request declares the one media type the client metadata is read in, as <see cref="ConsumesAttribute"/>
	/// decides it.
	/// </summary>
	private static bool DeclaresJson(HttpRequest request)
		=> request.ContentType is { } contentType && new MediaType(contentType).IsSubsetOf(Json);

	/// <summary>
	/// Records the refusal of the body and leaves the body unread, so the refusal is answered once the token is judged:
	/// the token decides first whether the request may be answered about its body at all.
	/// </summary>
	private static async Task RefuseAsync(
		ResourceExecutingContext context, ResourceExecutionDelegate next, ActionResult refusal)
	{
		context.HttpContext.Features.Set(new ClientMetadataRefusal(refusal));

		var request = context.HttpContext.Request;
		request.Body = Stream.Null;
		request.ContentLength = 0;

		await next();
	}

	private static async Task<long> CopyAtMostAsync(
		Stream source, Stream destination, long maxBytes, CancellationToken cancellationToken)
	{
		var buffer = new byte[8192];
		var total = 0L;

		while (total < maxBytes)
		{
			var wanted = (int)Math.Min(buffer.Length, maxBytes - total);
			var read = await source.ReadAsync(buffer.AsMemory(0, wanted), cancellationToken);
			if (read == 0)
				break;

			await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
			total += read;
		}

		return total;
	}
}
