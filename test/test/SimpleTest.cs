using NUnit.Framework;
using System.IO;
using System.Reflection;

namespace Org.BouncyCastle.Utilities.Test
{
    public abstract class SimpleTest
    {
        internal void Fail(string message) => Assert.Fail(message);

		internal static Stream GetTestDataAsStream(string name)
		{
			string fullName = GetFullName(name);            
			return typeof(SimpleTest).GetTypeInfo().Assembly.GetManifestResourceStream(fullName);
		}

		private static string GetFullName(string name)
		{
            return "InflatablePalace.Test.data." + name;
		}
    }
}
