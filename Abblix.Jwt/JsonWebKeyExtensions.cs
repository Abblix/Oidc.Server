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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// Provides extension methods for the JsonWebKey model to simplify the process of populating its properties from different sources.
/// These methods enable easy conversion between JsonWebKey and various cryptographic representations.
/// </summary>
public static class JsonWebKeyExtensions
{
	/// <summary>
	/// Converts an X509Certificate2 to a JsonWebKey. The private keys can be optionally included in the conversion.
	/// </summary>
	/// <param name="certificate">The X509Certificate2 to convert.</param>
	/// <param name="includePrivateKeys">Indicates whether to include private keys in the conversion.</param>
	/// <returns>A JsonWebKey representing the certificate.</returns>
	public static JsonWebKey ToJsonWebKey(this X509Certificate2 certificate, bool includePrivateKeys = false)
	{
		// Try ECDSA first
		var ecdsaPublicKey = certificate.GetECDsaPublicKey();
		if (ecdsaPublicKey != null)
		{
			var ecdsaPrivateKey = includePrivateKeys ? certificate.GetECDsaPrivateKey() : null;

			var jwk = new EllipticCurveJsonWebKey
			{
				Usage = ExtractKeyUsage(certificate),
				Algorithm = null, // Algorithm not determined from certificate alone
				KeyId = certificate.Thumbprint,
			}
				.Apply(ecdsaPublicKey.ExportParameters(false))
				.Apply(certificate);

			if (ecdsaPrivateKey != null)
			{
				jwk = jwk.Apply(ecdsaPrivateKey.ExportParameters(true));
			}

			return jwk;
		}

		// Fall back to RSA
		var rsaPublicKey = certificate.GetRSAPublicKey();
		if (rsaPublicKey != null)
		{
			var rsaPrivateKey = includePrivateKeys ? certificate.GetRSAPrivateKey() : null;

			var jwk = new RsaJsonWebKey
			{
				Usage = ExtractKeyUsage(certificate),
				Algorithm = null, // Algorithm not determined from certificate alone
				KeyId = certificate.Thumbprint,
			}.Apply(rsaPublicKey.ExportParameters(false)).Apply(certificate);

			if (rsaPrivateKey != null)
			{
				jwk = jwk.Apply(rsaPrivateKey.ExportParameters(true));
			}

			return jwk;
		}

		throw new InvalidOperationException($"Certificate does not contain a supported public key algorithm");
	}

	/// <summary>
	/// Extracts key usage from X509Certificate2.
	/// Determines whether the key is used for signing, encryption, or both.
	/// </summary>
	private static string ExtractKeyUsage(X509Certificate2 certificate)
	{
		const string defaultUsage = PublicKeyUsages.Signature;

		var keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
		if (keyUsage == null)
			return defaultUsage;

		var sig = keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature);
		var enc = keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment);
		return (sig, enc) switch
		{
			(true, true) => $"{PublicKeyUsages.Signature} {PublicKeyUsages.Encryption}",
			(true, false) => PublicKeyUsages.Signature,
			(false, true) => PublicKeyUsages.Encryption,
			_ => defaultUsage,
		};
	}

	/// <summary>
	/// Applies X509Certificate2 properties to a JsonWebKey.
	/// </summary>
	/// <typeparam name="T">The type of JsonWebKey (must be a subclass).</typeparam>
	/// <param name="jwk">The JsonWebKey to which the certificate properties are to be applied.</param>
	/// <param name="certificate">The X509Certificate2 providing the properties.</param>
	/// <returns>The updated JsonWebKey with applied certificate properties.</returns>
	public static T Apply<T>(this T jwk, X509Certificate2 certificate) where T : JsonWebKey
	{
		jwk.Certificates = [certificate.RawData];
		jwk.Thumbprint = certificate.GetCertHash();
		return jwk;
	}

	/// <summary>
	/// Applies RSA parameters to an RsaJsonWebKey.
	/// </summary>
	/// <param name="jwk">The RsaJsonWebKey to which the RSA parameters are to be applied.</param>
	/// <param name="parameters">The RSAParameters providing the RSA key information.</param>
	/// <returns>The updated RsaJsonWebKey with applied RSA parameters.</returns>
	public static RsaJsonWebKey Apply(this RsaJsonWebKey jwk, RSAParameters parameters)
	{
		jwk.Exponent = parameters.Exponent;
		jwk.Modulus = parameters.Modulus;

		jwk.PrivateExponent = parameters.D;
		jwk.FirstPrimeFactor = parameters.P;
		jwk.SecondPrimeFactor = parameters.Q;
		jwk.FirstFactorCrtExponent = parameters.DP;
		jwk.SecondFactorCrtExponent = parameters.DQ;
		jwk.FirstCrtCoefficient = parameters.InverseQ;

		return jwk;
	}

	/// <summary>
	/// Applies Elliptic Curve parameters to an EllipticCurveJsonWebKey.
	/// </summary>
	/// <param name="jwk">The EllipticCurveJsonWebKey to which the EC parameters are to be applied.</param>
	/// <param name="parameters">The ECParameters providing the Elliptic Curve key information.</param>
	/// <returns>The updated EllipticCurveJsonWebKey with applied Elliptic Curve parameters.</returns>
	public static EllipticCurveJsonWebKey Apply(this EllipticCurveJsonWebKey jwk, ECParameters parameters)
	{
		var curveOid = parameters.Curve.Oid;

		jwk.Curve = curveOid.Value switch
		{
			EllipticCurveOids.P256 => EllipticCurveTypes.P256,
			EllipticCurveOids.P384 => EllipticCurveTypes.P384,
			EllipticCurveOids.P521 => EllipticCurveTypes.P521,
			_ => throw new InvalidOperationException($"The OID [{curveOid.Value}] {curveOid.FriendlyName} is not supported"),
		};

		jwk.X = parameters.Q.X;
		jwk.Y = parameters.Q.Y;

		if (parameters.D != null)
			jwk.PrivateKey = parameters.D;

		return jwk;
	}

	/// <summary>
	/// Converts an RsaJsonWebKey to an RSA object, which represents an RSA public and private key pair or just a public key.
	/// </summary>
	/// <param name="key">The RsaJsonWebKey to be converted.</param>
	/// <returns>An RSA object based on the provided RsaJsonWebKey.</returns>
	public static RSA ToRsa(this RsaJsonWebKey key)
	{
		var rsa = RSA.Create();
		rsa.ImportParameters(key.ToRsaParameters());
		return rsa;
	}

	/// <summary>
	/// Converts an RsaJsonWebKey to RSAParameters, which represent the key parameters used in RSA cryptographic operations.
	/// </summary>
	/// <param name="key">The RsaJsonWebKey to be converted.</param>
	/// <returns>An RSAParameters object based on the provided RsaJsonWebKey.</returns>
	public static RSAParameters ToRsaParameters(this RsaJsonWebKey key) => new()
	{
		Modulus = key.Modulus,
		Exponent = key.Exponent,
		D = key.PrivateExponent,
		P = key.FirstPrimeFactor,
		Q = key.SecondPrimeFactor,
		DP = key.FirstFactorCrtExponent,
		DQ = key.SecondFactorCrtExponent,
		InverseQ = key.FirstCrtCoefficient,
	};

	/// <summary>
	/// Converts an EllipticCurveJsonWebKey to an ECDsa object,
	/// which represents an ECDSA public and private key pair or just a public key.
	/// </summary>
	/// <param name="key">The EllipticCurveJsonWebKey to be converted.</param>
	/// <returns>An ECDsa object based on the provided EllipticCurveJsonWebKey.</returns>
	public static ECDsa ToEcdsa(this EllipticCurveJsonWebKey key)
	{
		var ecdsa = ECDsa.Create();
		ecdsa.ImportParameters(key.ToEcParameters());
		return ecdsa;
	}

	/// <summary>
	/// Converts an EllipticCurveJsonWebKey to ECParameters,
	/// which represent the key parameters used in ECDSA cryptographic operations.
	/// Supports P-256, P-384, and P-521 curves as defined in NIST standards.
	/// </summary>
	/// <param name="key">The EllipticCurveJsonWebKey to be converted.</param>
	/// <returns>An ECParameters object based on the provided EllipticCurveJsonWebKey.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the curve type is not supported.</exception>
	public static ECParameters ToEcParameters(this EllipticCurveJsonWebKey key)
	{
		var curve = key.Curve switch
		{
			EllipticCurveTypes.P256 => ECCurve.NamedCurves.nistP256,
			EllipticCurveTypes.P384 => ECCurve.NamedCurves.nistP384,
			EllipticCurveTypes.P521 => ECCurve.NamedCurves.nistP521,
			_ => throw new InvalidOperationException(
				$"Unsupported elliptic curve: {key.Curve}. " +
				$"Supported curves: {EllipticCurveTypes.P256}, {EllipticCurveTypes.P384}, {EllipticCurveTypes.P521}"),
		};

		return new ECParameters
		{
			Curve = curve,
			Q = new ECPoint
			{
				X = key.X ?? throw new InvalidOperationException("X coordinate is required for elliptic curve key"),
				Y = key.Y ?? throw new InvalidOperationException("Y coordinate is required for elliptic curve key"),
			},
			D = key.PrivateKey, // Optional private key component
		};
	}
}
