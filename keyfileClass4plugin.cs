/*
  keyfileClass for Project KeyManagerRSA
  stripped to needs for "Multi (RSA) Cert Key Provider for KeePass"
  Copyright (C) 2012 Dirk Heitzmann <MultiCertKeyProvider (a-t) c-wd.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  In addition :
    Uncommercial, personnel use is free.
    For commercial use see Copyright.
    Removing of information about Copyright is prohibited.

*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;


namespace MultiCertKeyProvider
{
    public class keyfileClass 
    {
        //----------------------
        private XDocument p_keyfile = new XDocument();
        public XDocument Keyfile
        {
            get { return p_keyfile; }
            set { p_keyfile = value; }
        }
        
        private XElement p_keyfileRoot = null;
        public XElement keyfileRoot
        {
            get { return p_keyfileRoot; }
            set { p_keyfileRoot = value; }
        }

        //----------------------
        private IEnumerable<XElement> p_XCryptedKeys = null;
        public IEnumerable<XElement> XCryptedKeys
        {
            get { return p_XCryptedKeys; }
            set { p_XCryptedKeys = value; }
        }

        //----------------------
        private byte[] p_AESKey;
        public byte[] AESKey
        {
            get { return p_AESKey; }
            set { p_AESKey = value; }
        }
        private String p_AESKeyBase64 = "";
        public String AESKeyBase64
        {
            get { return p_AESKeyBase64; }
            set { p_AESKeyBase64 = value; }
        }

        private String p_AESKeyHash = "";
        public String AESKeyHash
        {
            get { return p_AESKeyHash; }
            set { p_AESKeyHash = value; }
        }

        //----------------------
        private XElement p_XDecryptedKey = null;
        public XElement XDecryptedKey
        {
            get { return p_XDecryptedKey; }
            set { p_XDecryptedKey = value; }
        }
        private String p_XDecryptedKey_Subject;
        public String XDecryptedKey_Subject
        {
            get { return p_XDecryptedKey_Subject; }
            set { p_XDecryptedKey_Subject = value; }
        }
        private String p_XDecryptedKey_Key;
        public String XDecryptedKey_Key
        {
            get { return p_XDecryptedKey_Key; }
            set { p_XDecryptedKey_Key = value; }
        }

        //----------------------
        private X509Certificate2 p_DecryptRSACert;
        public X509Certificate2 DecryptRSACert
        {
            get { return p_DecryptRSACert; }
            set { p_DecryptRSACert = value; }
        }

        //----------------------
        private String p_DecAESKeyBase64 = "";
        public String DecAESKeyBase64
        {
            get { return p_DecAESKeyBase64; }
            set { p_DecAESKeyBase64 = value; }
        }
        private String p_DecAESKeyHash = "";
        public String DecAESKeyHash
        {
            get { return p_DecAESKeyHash; }
            set { p_DecAESKeyHash = value; }
        }

        //----------------------
        private String p_filename = "";
        public String filename
        {
            get { return p_filename; }
            set { p_filename = value; }
        }


        // Stati
        Boolean p_statLoaded = false;
        public Boolean statLoaded
        {
            get { return p_statLoaded; }
            set { p_statLoaded = value;     }
        }
        Boolean p_statDecrypted = false;
        public Boolean statDecrypted
        {
            get { return p_statDecrypted; }
            set { p_statDecrypted = value; }
        }


        //----------------------
        public void OpenKeyfile()
        {
            if (p_filename.Length == 0)                
                throw new FileNotFoundException ("Keyfile : Filename not set.");
            try
            {
                p_keyfile = XDocument.Load(p_filename);
                p_keyfileRoot = p_keyfile.Element("CryptedKeys");

                XAttribute p_XAKeyHash = p_keyfileRoot.Attribute("KeyHash");
                this.p_AESKeyHash = p_XAKeyHash.Value;

                this.p_XCryptedKeys = p_keyfileRoot.Elements("CryptedKey");

                if (this.XCryptedKeys != null)
                    p_statLoaded = true;
            }
            catch (FileNotFoundException)
            {
                p_statLoaded = false;
                throw new FileNotFoundException("Unable to load keyfile.");
            }
        }

        public void CreateKeyfile()
        {
            if (RSASelectCertificate())
                CreateKeyfile(p_DecryptRSACert);
        }
        public void CreateKeyfile(X509Certificate2 p_certificate)
        {
            if (p_filename.Length == 0)                
                throw new FileNotFoundException ("ERROR : Keyfile - Filename not set.");
            if (File.Exists(p_filename))
                throw new FileLoadException("ERROR : Keyfile - File already exist.");

            this.AESGenerate(256);
            this.GetMD5Hash();

            p_keyfile = new XDocument(
                new XDeclaration("1.0", "utf-8", "yes"),
                new XComment("Keyfile for MultiCertKeyProvider, (c) Dirk Heitzmann, creativeit.eu"),
                new XElement("CryptedKeys",
                    new XAttribute("KeyHash", this.p_AESKeyHash),
                    new XElement("CryptedKey",
                        new XElement("Keyname",p_certificate.Subject),new XElement("Key",RSAEncryptKey(p_certificate))
                    )
                )
            );

            p_keyfile.Save(p_filename);
            this.OpenKeyfile();
        }


        public Boolean DecryptAESKeyWithRSA()
        {
            return DecryptAESKeyWithRSA(p_DecryptRSACert);
        }
        public Boolean DecryptAESKeyWithRSA(X509Certificate2 decryptCert)
        {
            try {
                XElement p_key = keyfileRoot.Descendants("Keyname")
                         .Where(n => (string)n == decryptCert.Subject)
                         .First();
                p_XDecryptedKey = p_key.Ancestors("CryptedKey").First();

                if (p_XDecryptedKey.HasElements) 
                {
                    p_XDecryptedKey_Subject = p_XDecryptedKey.Element("Keyname").Value;
                    p_XDecryptedKey_Key = p_XDecryptedKey.Element("Key").Value;
                    
                    p_DecAESKeyBase64 = this.RSADecryptKey(p_XDecryptedKey_Key, decryptCert);
                    p_DecAESKeyHash = this.GetMD5Hash(p_DecAESKeyBase64);

                    if (p_DecAESKeyHash.Equals(p_AESKeyHash))
                    {
                        p_AESKeyBase64 = p_DecAESKeyBase64;
                        p_AESKey = Convert.FromBase64String(ASCIIEncoding.UTF8.GetString(Convert.FromBase64String(p_DecAESKeyBase64)).Split(',')[1]);

                        p_statDecrypted = true;
                    }
                    return true;
                } 
                else 
                {
                    return false;
                }
            }
            catch(InvalidOperationException) 
            {
                return false;
            }
        }


        // ------------------------------------------------------
        // AES Stuff (AESGenerate, AESEncrypt, AESDecrypt)
        // TODO : AESEncrypt, AESDecrypt anpassen

        public string AESGenerate(int keySize)
        {
            RijndaelManaged aesEncrypt = new RijndaelManaged();
            aesEncrypt.KeySize = keySize;
            aesEncrypt.BlockSize = 128;
            aesEncrypt.Mode = CipherMode.CBC;
            aesEncrypt.Padding = PaddingMode.PKCS7;
            aesEncrypt.GenerateIV();
            string ivStr = Convert.ToBase64String(aesEncrypt.IV);
            aesEncrypt.GenerateKey();
            string keyStr = Convert.ToBase64String(aesEncrypt.Key);

            Console.WriteLine("Using key '{0}'", keyStr, ivStr);           
            Console.WriteLine("Using iv '{0}'", ivStr);           
            string completeKey = ivStr + "," + keyStr;

            this.p_AESKey = aesEncrypt.Key;
            this.p_AESKeyBase64 = Convert.ToBase64String(ASCIIEncoding.UTF8.GetBytes(completeKey));
            return this.p_AESKeyBase64;
        }

        // ------------------------------------------------------
        // MD5 Stuff

        public string GetMD5Hash()
        {
            return GetMD5Hash(this.p_AESKeyBase64);
        } 
        public string GetMD5Hash(string TextToHash)
        {
            //Prüfen ob Daten übergeben wurden.
            if ((TextToHash == null) || (TextToHash.Length == 0))
            {
                 return string.Empty;
            }
            //MD5 Hash aus dem String berechnen. Dazu muss der string in ein Byte[]
            //zerlegt werden. Danach muss das Resultat wieder zurück in ein string.
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] textToHash = Encoding.Default.GetBytes(TextToHash);
            byte[] result = md5.ComputeHash(textToHash);

            this.p_AESKeyHash = System.BitConverter.ToString(result);
            return this.p_AESKeyHash;
        }

        // ------------------------------------------------------
        // RSA

        public Boolean RSASelectCertificate()
        {
            X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
            X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
            fcollection = (X509Certificate2Collection)fcollection.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.DataEncipherment, true);
            X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(fcollection, "Certificate Select", "Select a certificate from the following list", X509SelectionFlag.SingleSelection);

            if (scollection.Count == 0)
            {
                throw new ArgumentOutOfRangeException("ERROR : No certificate selected.");
            }
            if (!scollection[0].HasPrivateKey)
            {
                throw new CryptographicException("ERROR : Certificate contains no private key.");
            }

            p_DecryptRSACert = scollection[0];
            store.Close();

            return true;
        }

        public string RSAEncryptKey(X509Certificate2 certificate)
        {
            return RSAEncryptKey(this.p_AESKeyBase64, certificate);
        }
        public string RSAEncryptKey(String String2Encrypt, X509Certificate2 certificate)
        {
            var rsa = certificate.GetRSAPublicKey();

            string PlainString = String2Encrypt.Trim();
            byte[] cipherbytes = ASCIIEncoding.ASCII.GetBytes(PlainString);

            byte[] cipher = rsa.Encrypt(cipherbytes, RSAEncryptionPadding.Pkcs1);
            return Convert.ToBase64String(cipher);
        }

        public String RSADecryptKey(String String2Decrypt, X509Certificate2 certificate)
        {
            var rsa = certificate.GetRSAPrivateKey();

            byte[] cipherbytes = Convert.FromBase64String(String2Decrypt);
            byte[] plainbytes = rsa.Decrypt(cipherbytes, RSAEncryptionPadding.Pkcs1);

            ASCIIEncoding enc = new ASCIIEncoding();
            return enc.GetString(plainbytes);
        }

    }
}
