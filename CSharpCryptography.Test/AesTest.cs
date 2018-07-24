using CSharpCryptography.Aes;
using CSharpCryptography.Shared;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace CSharpCryptography.Test
{
    [TestClass]
    public class AesTest : BaseEncryptionAttributes
    {
        public AesTest()
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
        public void EncryptString()
        {
            var encrypted = AesUtility.EncryptStringToBytes_Aes(originalText, Key, IV);

            Assert.AreNotEqual(originalText, encrypted.ToString());
        }

        [TestMethod]
        public void DecryptString()
        {
            var encrypted = AesUtility.EncryptStringToBytes_Aes(originalText, Key, IV);
            var decryptedString = AesUtility.DecryptStringFromBytes_Aes(encrypted, Key, IV);

            Assert.AreEqual(originalText, decryptedString);
        }
    }
}
