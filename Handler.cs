using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Text.Json;
using SmallTool_MSIPC.Models;
using System.Linq;
using System.Data.SQLite;
using System.Data;


namespace SmallTool_MSIPC
{
    class Handler
    {
        private readonly string ProgramLocation = System.AppDomain.CurrentDomain.BaseDirectory;
        private string CurrentLogFile;
        private static SQLiteConnection db = new SQLiteConnection("DataSource = database.db; Version = 3;");
        private readonly static Dictionary<string, string> ColumnFilter = InitializeColumnFilter();
        
        public void InitializeLogFile()
        {
            string LogPath = ProgramLocation + @"\Logs\";
            Directory.CreateDirectory(LogPath);

            string[] LogFiles = Directory.GetFiles(LogPath, "Log-*");
            if (LogFiles.Length > 0)
            {
                List<string> Files = LogFiles.ToList();
                int FileNumber = 0;
                foreach (string file in Files)
                {
                    Int32.TryParse(file.Split('\\')[^1].Split('-')[^1].Split('.')[0], out int TempFileNumber);
                    if (TempFileNumber > FileNumber) { FileNumber = TempFileNumber; }
                }

                FileNumber++;
                CurrentLogFile = LogPath + "Log-" + FileNumber + ".log";
                File.Create(CurrentLogFile).Close();
            }
            else
            {
                CurrentLogFile = LogPath + @"Log-1.log";
                File.Create(CurrentLogFile).Close();
            }
        }

        //try to complete the validated MSIPC folder path
        public string LocationValidator(string Location, bool LogOnly)
        {
            if (!Directory.Exists(Location))
            {
                return "";
            }
            //check if it is a MSIPC folder already
            if (!LogOnly)
            {
                if (!Directory.EnumerateFiles(Location, "CERT-Machine.drm").Any())
                {
                    // check if it an upper folder
                    if (Directory.Exists(Location + @"MSIPC\") && File.Exists(Location + @"MSIPC\CERT-Machine.drm"))
                    {
                        return Location + @"MSIPC\";
                    }
                    else
                    {
                        return "";
                    }

                }
            }
            else 
            {
                if (!Directory.EnumerateFiles(Location, "*.ipclog").Any())
                { 
                    return "";
                }
            }
            return Location;
        }

        public string Serialize(Object input)
        {
            string Output = JsonSerializer.Serialize(input, new JsonSerializerOptions());

            return Output;
        }

        public MSIPC_Rules DeserializeRules(string ProgramLocation)
        {
            try
            {
                return JsonSerializer.Deserialize<MSIPC_Rules>(File.ReadAllText(ProgramLocation + "rules.json"));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return new MSIPC_Rules();
            }
        }

        public string XmlValidator(string Location)
        {
            string content = File.ReadAllText(Location, Encoding.Unicode);
            content = content.Replace("\x00", "[0x00]").Replace(@"\0", "");
            content = "<WRAPPER>" + content + @"</WRAPPER>";
            return content;
        }

        public void TxtLogger(string[] input)
        {
            try
            {
                foreach (string item in input)
                {
                    File.AppendAllText(CurrentLogFile, DateTime.Now.ToString() + "    " + item + "\n");
                    //Trace.Flush();
                }
            }
            catch (Exception e)
            {
                File.AppendAllText(CurrentLogFile, DateTime.Now.ToString() + e);
            }
        }

        public void TxtLogger(string input)
        {
            try
            {
                File.AppendAllText(CurrentLogFile, DateTime.Now.ToString() + "    " + input + "\n");
                //Trace.Flush();
            }
            catch (Exception e)
            {
                File.AppendAllText(CurrentLogFile, DateTime.Now.ToString() + e + "\n");
            }
        }

        private static DataTable DBSet()
        {
            db.Open();

            string sql = "select * from test";
            SQLiteCommand command = new SQLiteCommand(sql, db);
            SQLiteDataReader reader = command.ExecuteReader();

            DataTable dt = new DataTable("Filter");

            if (reader.HasRows)
            {
                dt.Load(reader);
            }

            db.Close();

            return dt;
        }

        private static Dictionary<string,string> InitializeColumnFilter()
        {
            db.Open();

            string sql = "select * from test";
            SQLiteCommand command = new SQLiteCommand(sql, db);
            SQLiteDataReader reader = command.ExecuteReader();

            DataTable dt = new DataTable("Filter");

            if (reader.HasRows)
            {
                dt.Load(reader);
            }

            db.Close();

            Dictionary<string, string> output = new Dictionary<string, string>();

            foreach (DataRow row in dt.Rows)
            {
                output.Add(row["name"].ToString(), row["value"].ToString());
            }

            return output;
        }

        public bool IsFiltered(string input, string KeyWord)
        {
            return input.StartsWith(ColumnFilter[KeyWord]);
        }

        public bool IsFiltered(string input, string[] KeyWord)
        {
            bool output = false;
            foreach (string word in KeyWord)
            {
                if (IsFiltered(input, word))
                {
                    return true;
                }
            }
            return output;
        }

        //public bool IsMSIPCRequest(string input)
        //{
        //    //return input.StartsWith("Initializing an HTTP request with Win");
        //    string KeyWord = ColumnFilter["MSIPC_Request"];
        //    return IsFiltered(input, KeyWord);
        //}

        //public bool IsMSIPCReponse(string input)
        //{
        //    //return input.StartsWith("------ Sending Request done. HTTP Status code = ");
        //    string KeyWord = ColumnFilter["MSIPC_Response"];
        //    return IsFiltered(input, KeyWord);
        //}

        //public bool IsMSIPCCorrelation(string input)
        //{
        //    //return input.StartsWith("Correlation-Id/Request-Id:");
        //    string KeyWord = ColumnFilter["MSIPC_Correlation"];
        //    return IsFiltered(input, KeyWord);
        //}

        //public bool IsMSIPCBasicLog(string input)
        //{
        //    return IsMSIPCRequest(input) || IsMSIPCReponse(input) || IsMSIPCCorrelation(input);
        //}
    }
}
