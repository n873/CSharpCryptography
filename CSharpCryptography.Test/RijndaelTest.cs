using CSharpCryptography.Rijndael;
using CSharpCryptography.Shared;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace CSharpCryptography.Test
{
    [TestClass]
    public class RijndaelTest : BaseEncryptionAttributes
    {
        public RijndaelTest()
        {
            using (var myRijndael = new RijndaelManaged())
            {
                myRijndael.GenerateKey();
                myRijndael.GenerateIV();
                Key = myRijndael.Key;
                IV = myRijndael.IV;
            }
        }

        [TestMethod]
        public void EncryptString() {
            var encrypted = RijndaelUtility.EncryptStringToBytes_Rijndael(originalText, Key, IV);

            Assert.AreNotEqual(originalText, encrypted.ToString());
        }

        [TestMethod]
        public void DecryptString() {
            var encrypted = RijndaelUtility.EncryptStringToBytes_Rijndael(originalText, Key, IV);
            var decryptedString = RijndaelUtility.DecryptStringFromBytes_Rijndael(encrypted, Key, IV);

            Assert.AreEqual(originalText, decryptedString);
        }
    }
}
