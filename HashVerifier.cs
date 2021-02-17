using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using static System.Console;

namespace HashDemo
{
	public class HashVerifier
	{
		#region Public Methods

		/// <summary>
		/// Verifies hash sums of the files.
		/// </summary>
		/// <param name="pathToHashSumsContainingFile">The path to the file containing hash sums to verify.</param>
		/// <param name="pathToDirectoryOfFilesToVerify">The path to the directory containing files to verify.</param>
		public static void VerifyFilesHashSums(string pathToHashSumsContainingFile, string pathToDirectoryOfFilesToVerify)
		{
			if (File.Exists(pathToHashSumsContainingFile) == false)
			{
				WriteLine("The file containing hash sums doesn't exist.");
				return;
			}
			if (Directory.Exists(pathToDirectoryOfFilesToVerify) == false)
			{
				WriteLine("The directory containing files to verify doesn't exist.");
				return;
			}

			// Enforce the structure of the file containing hash sums:
			//
			// <fileName(no spaces, require extension, allow rows/lines with the same file name)>
			// <hashType(md5|sha1|sha256)>
			// <hashSum(length: md5:32 sha1:40 sha256:64, charSet-hex:[a-f0-9])>
			// (case insensitive regex)
			//
			// Match 3 groups (fileNameWithExtension, hashType, hashSum)
			//
			// example.bin md5 0123456789abcdef0123456789abcdef

			string input;

			try
			{
				input = File.ReadAllText(pathToHashSumsContainingFile);
			}
			catch (Exception ex)
			{
				WriteLine($"Failed to read from the file containing hash sums.\nException message: {ex.Message}");
				return;
			}

			var pattern = "^" +
				@"(?<grFileNameWithExtension>[^\s\.]*\.[^\s\.]*)" + " " +
				@"(?<grHashType>(?<md5>md5)|(?<sha1>sha1)|(?<sha256>sha256))" + " " +
				@"(?<grHashSum>(?(md5)[a-f0-9]{32}|(?(sha1)[a-f0-9]{40}|(?(sha256)[a-f0-9]{64}))))" + "\r?$";

			var matches = Regex.Matches(input, pattern, RegexOptions.Multiline | RegexOptions.IgnoreCase);

			if (matches.Count == 0)
			{
				WriteLine("The file containing hash sums is empty or its structure is invalid.");
			}
			else
			{
				foreach (Match match in matches)
				{
					HandleMatch(pathToDirectoryOfFilesToVerify,
						fileName: match.Groups["grFileNameWithExtension"].Value,
						hashType: match.Groups["grHashType"].Value,
						hashToVerify: match.Groups["grHashSum"].Value);
				}
			}

			WriteLine();
			WriteLine("If some files are missing from the output, make sure that for each line of the file containing hash sums:");
			WriteLine();
			WriteLine("- the file name doesn't contain spaces.");
			WriteLine("- the file extension is specified.");
			WriteLine("- the hash type/algorithm is either md5, sha1 or sha256 (case-insensitive).");
			WriteLine("- the hash is hexadecimal-formatted.");
			WriteLine("- the hash character set is [a-fA-F0-9].");
			WriteLine("- the hash character amount matches the hash type/algorithm (md5:32, sha1:40, sha256:64).");
			WriteLine();
			WriteLine("Valid line example:");
			WriteLine("filename.extension md5 0123456789abcdef0123456789abcdef");
		}

		#endregion

		#region Private Methods

		/// <summary>
		/// Displays the message regarding the file hash sum verification.
		/// </summary>
		/// <param name="pathToDirectoryOfFilesToVerify">The path to the directory containing files to verify.</param>
		/// <param name="fileName">The name of the file (including the file extension).</param>
		/// <param name="hashType">The hash type/algorithm to use for hash verifying.</param>
		/// <param name="hashToVerify">The hash to verify.</param>
		private static void HandleMatch(string pathToDirectoryOfFilesToVerify, string fileName, string hashType, string hashToVerify)
		{
			// The message to display to the right of the file name.
			string message;

			var pathToFile = $"{pathToDirectoryOfFilesToVerify}\\{fileName}";

			if (File.Exists(pathToFile) == false)
			{
				// The file doesn't exist.

				message = "NOT FOUND";
			}
			else
			{
				message = VerifyHash(pathToFile, hashType, hashToVerify) ? "OK" : "FAIL";
			}

			WriteLine($"{fileName} {message}");
		}

		/// <summary>
		/// Computes the hash for the file and returns <see langword="true"/> if the computed hash is equal to the provided hash; otherwise, <see langword="false"/>.
		/// </summary>
		/// <param name="pathToFile">The path to the file to verify.</param>
		/// <param name="hashType">The hash type/algorithm to use for hash verifying.</param>
		/// <param name="hashToVerify">The hash to verify.</param>
		private static bool VerifyHash(string pathToFile, string hashType, string hashToVerify)
		{
			using var hashAlgorithm = GetHashAlgorithm(hashType);
			using var stream = File.OpenRead(pathToFile);

			var hash = hashAlgorithm.ComputeHash(stream);

			var hashHex = BitConverter.ToString(hash).Replace("-", "");

			return string.Equals(hashHex, hashToVerify, StringComparison.OrdinalIgnoreCase);
		}

		/// <summary>
		/// Returns the <see cref="HashAlgorithm"/> corresponding to the provided hash type string.
		/// </summary>
		/// <param name="hashType">The hash type/algorithm string.</param>
		private static HashAlgorithm GetHashAlgorithm(string hashType)
		{
			return hashType.ToLower() switch
			{
				"md5" => MD5.Create(),
				"sha1" => SHA1.Create(),
				"sha256" => SHA256.Create(),
				_ => throw new NotImplementedException()
			};
		}

		#endregion
	}
}
