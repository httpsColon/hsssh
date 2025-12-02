using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;


namespace HSssh
{
    public  class Auth
    {
        public static string GetCIdViaPowerShell()
        {
            try
            {
                var process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "powershell";
                process.StartInfo.Arguments = "-Command \"Get-CimInstance Win32_Processor | Select-Object -ExpandProperty ProcessorId\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                return output.Trim();
            }
            catch
            {
                return "GetCIdViaPowerShell Error";
            }
        }

        public static string GetCIdViaCommand()
        {
            try
            {
                // 检查 wmic 是否存在
                var wmicPath = Environment.ExpandEnvironmentVariables(@"%WINDIR%\System32\wbem\wmic.exe");
                if (!System.IO.File.Exists(wmicPath))
                    return GetCIdViaPowerShell();

                var process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "wmic";
                process.StartInfo.Arguments = "cpu get ProcessorId /value";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // 兼容多种输出格式
                foreach (var line in output.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("ProcessorId=", StringComparison.OrdinalIgnoreCase))
                    {
                        var parts = trimmed.Split('=');
                        if (parts.Length == 2)
                            return parts[1].Trim();
                    }
                }
                return GetCIdViaPowerShell();
                //return "wmic NotFound";
            }
            catch
            {
                return "wmic Error";
            }
        }
        


        public static bool Au()
        {
            string cfg = Directory.GetCurrentDirectory() + @"\hsssh.cfg";
            string cid = GetCIdViaCommand();
            return cid =="BFEBFBFF000C0662";
            //return cid == RC4Helper.Decrypt(File.ReadAllBytes(cfg), "hsssh") || cid == RC4Helper.Decrypt2(File.ReadAllBytes(cfg), "hsssh");

        }

        public static string GetBId() 
        {
            try
            {
                string accountPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Battle.net",
                "Account"
                );

                // 检查基础路径是否存在
                if (!Directory.Exists(accountPath)) return "";

                // 定义纯数字正则匹配规则
                var numericRegex = new Regex(@"^\d+$");

                // 查询并处理文件夹
                return Directory.EnumerateDirectories(accountPath)
                    .Select(dir => new
                    {
                        Info = new DirectoryInfo(dir),
                        Name = Path.GetFileName(dir)
                    })
                    .Where(x => numericRegex.IsMatch(x.Name)) // 仅保留纯数字名称
                    .OrderByDescending(x => x.Info.LastWriteTime) // 按修改时间倒序
                    .FirstOrDefault()? // 取第一条记录
                    .Name ?? "";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"错误: {ex.Message}");
                return "";
            }
        }
    }


    public static class RC4Helper
    {
        /// <summary>
        /// RC4 加密（返回 Base64 字符串）
        /// </summary>
        public static string Encrypt(string plainText, string key)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedBytes = ProcessRC4(plainBytes, key);
            return Convert.ToBase64String(encryptedBytes);
        }

        /// <summary>
        /// RC4 解密（从 Base64 字符串解码）
        /// </summary>
        public static string Decrypt(byte[] encryptedBytes, string key)
        {
            // = Convert.FromBase64String(base64Text);
            byte[] decryptedBytes = ProcessRC4(encryptedBytes, key);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
        public static string Decrypt2(byte[] encryptedBytes, string key)
        {
            // = Convert.FromBase64String(base64Text);
            byte[] decryptedBytes = ProcessRC4(encryptedBytes, key);
            return Encoding.Default .GetString(decryptedBytes);
        }

        // RC4 核心处理算法
        private static byte[] ProcessRC4(byte[] data, string key)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] s = new byte[256];
            byte[] k = new byte[256];
            byte temp;
            int i, j;

            // 初始化 S 盒和临时密钥数组
            for (i = 0; i < 256; i++)
            {
                s[i] = (byte)i;
                k[i] = keyBytes[i % keyBytes.Length];
            }

            // 打乱 S 盒
            j = 0;
            for (i = 0; i < 256; i++)
            {
                j = (j + s[i] + k[i]) % 256;
                temp = s[i];
                s[i] = s[j];
                s[j] = temp;
            }

            // 生成密钥流并异或处理数据
            i = j = 0;
            byte[] result = new byte[data.Length];
            for (int idx = 0; idx < data.Length; idx++)
            {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;

                // 交换 S[i] 和 S[j]
                temp = s[i];
                s[i] = s[j];
                s[j] = temp;

                // 生成密钥流字节
                int t = (s[i] + s[j]) % 256;
                result[idx] = (byte)(data[idx] ^ s[t]);
            }

            return result;
        }
    }
}


