/*
  Multi (RSA) Cert Key Provider for KeePass 
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
using System.IO;
using System.Security.Permissions;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Forms;

using KeePass.Plugins;
using KeePass.Forms;
using KeePass.Resources;
using KeePassLib.Keys;
using KeePassLib.Cryptography;
using KeePassLib.Serialization;
// for UI
using KeePass.UI;
using KeePassLib.Utility;

namespace MultiCertKeyProvider
{
    public sealed class MultiCertKeyProviderExt : Plugin
    {
        private IPluginHost m_host = null;
        private MultiCertKeyProvider m_prov = new MultiCertKeyProvider();

        public override bool Initialize(IPluginHost host)
        {
            m_host = host;
            m_host.KeyProviderPool.Add(m_prov);
            return true;
        }

        public override void Terminate()
        {
            m_host.KeyProviderPool.Remove(m_prov);
        }
    }

    public sealed class MultiCertKeyProvider : KeyProvider
    {
        keyfileClass keyfile = new keyfileClass();

        public override string Name
        {
            get { return "Multiple Certificate Key Provider"; }
        }

        public override byte[] GetKey(KeyProviderQueryContext ctx)
        {
            try
            {
                // Open Keyfile
                keyfile.filename = UrlUtil.StripExtension(ctx.DatabaseIOInfo.Path) + ".kmx";

                if (!ctx.CreatingNewKey)
                {
                    keyfile.OpenKeyfile();
                    keyfile.RSASelectCertificate();
                }
                else
                    keyfile.CreateKeyfile();

                if (keyfile.statLoaded)
                    keyfile.DecryptAESKeyWithRSA();
                else
                    throw new FileNotFoundException("Unable to load keyfile.");

                if (keyfile.statDecrypted)
                    return keyfile.AESKey;
                else
                    throw new CryptographicException("Unable to decrypt key.");

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                return null;
            }
        }

    }
}
