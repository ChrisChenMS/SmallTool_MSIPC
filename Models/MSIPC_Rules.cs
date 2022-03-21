using System;
using System.Collections.Generic;
using System.Text;

namespace SmallTool_MSIPC.Models
{
    public class MSIPC_Rules
    {
        public bool LogOnly { get; set; }

        public string ResponseType { get; set; }

        public string[] ResponseCodeList { get; set; }

        public bool CertAnalyse { get; set; }
        
        public bool LogAnalyse { get; set; }

        // Mode 
        // 0 Invalid
        // 1 Encryption
        // 2 Decryption
        // 3 All
        // 4 None
        public int Mode { get; set; }

        public bool Bootstrap { get; set; }

        public bool Template { get; set; }

        public bool RAC_CLC { get; set; }

        public bool EUL { get; set; }

        public CertRule CertRules { get; set; }

        public void Initialize()
        {
            if (LogAnalyse)
            {
                //LogAnalyse will analyse bootstrap
                this.Bootstrap = true;

                //if ResponseType or CodeList is not valid, initialize ResponseType with "exclude" and CodeList with []
                if (!(this.ResponseType.Length > 0) || !(this.ResponseCodeList.Length > 0))
                {
                    this.ResponseType = "exclude"; 
                    this.ResponseCodeList = new string[] { };
                }
                switch (Mode)
                {
                    //initialize log related rules
                    case 1:
                        this.Template = true;
                        this.RAC_CLC = true;
                        this.EUL = false;
                        break;
                    case 2:
                        this.Template = false;
                        this.RAC_CLC = false;
                        this.EUL = true;
                        break;
                    case 3:
                        this.Template = true;
                        this.RAC_CLC = true;
                        this.EUL = true;
                        break;
                    case 4:
                        this.Bootstrap = false;
                        this.Template = false;
                        this.RAC_CLC = false;
                        this.EUL = false;
                        break;
                    default:
                        this.Mode = 0;
                        break;
                }
            }
            if (LogOnly)
            {
                // LogOnly will not analyse certs
                this.CertAnalyse = false;
            }
        }
    }

    public class CertRule
    {
        public string[] RAC { get; set; }
        public string[] CLC { get; set; }
        public string[] EUL { get; set; }
    }
}
