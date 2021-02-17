using static System.Console;

namespace HashDemo
{
	class Program
	{
		static void Main(string[] args)
		{
			HashVerifier.VerifyFilesHashSums(pathToHashSumsContainingFile: args[0], pathToDirectoryOfFilesToVerify: args[1]);
			WriteLine();
			WriteLine("Press ENTER to finish.");
			ReadLine();
		}
	}
}
