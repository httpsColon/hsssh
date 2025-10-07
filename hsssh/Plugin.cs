using System;
using BepInEx;
using BepInEx.Configuration;
using BepInEx.Logging;
using Blizzard.GameService.SDK.Client.Integration;
using Blizzard.T5.Core.Time;
using HarmonyLib;
using Hearthstone.LookDev;
using UnityEngine;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;

namespace HSssh
{

    [HarmonyPatch(typeof(TimeScaleMgr))]
    public class TimeScaleMgrPatch
    {
        [HarmonyPrefix]
        [HarmonyPatch("Update")]
        static bool Update()
        {   
            return false;
        }
    }  
      
    [HarmonyPatch(typeof(BoardEventListener))]
    public class BoardEventListenerPatch
    {
        [HarmonyPrefix]
        [HarmonyPatch("TriggerAnimation")]
        static bool TriggerAnimation(string triggerName)
        {
            return false;
        }
    }
    
    public class PluginInfo
    {
        public const string PLUGIN_GUID = "com.my.HSssh";
        public const string PLUGIN_NAME = "HSssh";
        public const string PLUGIN_VERSION = "1.0.0";
    }
    
    [BepInPlugin(PluginInfo.PLUGIN_GUID, PluginInfo.PLUGIN_NAME, PluginInfo.PLUGIN_VERSION)]
    public class Plugin : BaseUnityPlugin 
    {
        KeyboardShortcut LeftControlS = new BepInEx.Configuration.KeyboardShortcut(KeyCode.S, KeyCode.LeftControl);
        [DllImport("user32.dll")]
        public static extern short GetAsyncKeyState(int vKey);

        private ConfigEntry<float> CfgTimeScale;
        
        
        public static new ManualLogSource Logger;
        public float Speed ;
        
        private IInput inputSystem;
        private void Awake()//在插件启动时会直接调用Awake()方法；
        {
            Logger = base.Logger;
            Logger.LogInfo($"Plugin {PluginInfo.PLUGIN_GUID} is loaded!");

            bool au = Auth.Au();
            Logger.LogInfo("HSssh initialized :" + au.ToString());

            if (!au)
            {
                Logger.LogInfo("HSssh cid :" + Auth.GetCIdViaCommand());
                Logger.LogInfo("HSssh bid :" + Auth.GetBId());
                Logger.LogInfo("HSssh decryp result :" + RC4Helper.Decrypt(File.ReadAllBytes(Directory.GetCurrentDirectory() + @"\hsssh.cfg"), "hsssh"));

                enabled = false;
            }

            
        }

        
        void Start()//在所有插件全部执行完成后会调用Start()方法，执行顺序在Awake()后面；
        {
            // Plugin startup logic
            CfgTimeScale = Config.Bind("Ctrl+S+数字键（0代表10倍，其他数字几就是几倍），pageUp/Down加减速，F5一键拔线，光标消失请按Esc", "变速倍率(一般3到5倍就够)", 1f, new ConfigDescription("变速齿轮倍速，范围：1到32", new AcceptableValueRange<float>(1, 32)));
            
            Harmony.CreateAndPatchAll(typeof(TimeScaleMgrPatch));
            
            
            Speed = CfgTimeScale.Value;
            inputSystem = new UnityInput();
        }

        

        private void ChongLian()
        {
            Logger.LogInfo("Triggering reconnect");
            //GameMgr.Get().RestartGame();
            GameServerInfo gs = Network.Get().GetLastGameServerJoined();
            Network.Get().DisconnectFromGameServer(Network.DisconnectReason.GameState_Reconnect);
            Network.Get().GotoGameServer(gs, true);
            SceneMgr.Get().ReloadMode();
        }
       
        private void OnDestroy()
        {
            Logger.LogError("::OnDestroy called!");
        }
        
        
        private void Update()
        {
            Speed = CfgTimeScale.Value;
            bool isKeyDown;
            if (inputSystem.GetKeyDown(KeyCode.F5, out isKeyDown))
            {
                ChongLian();
            }

            
            if (LeftControlS.IsDown())
            {

                Stopwatch timer = new Stopwatch();
                timer.Start();

                // 检测2秒
                while (timer.Elapsed.TotalSeconds < 2)
                {
                    // 遍历主键盘数字键（0x30到0x39）
                    for (int vk = 0x30; vk <= 0x39; vk++)
                    {
                        if ((GetAsyncKeyState(vk) & 0x8000) != 0)
                        {
                            int num = vk - 0x30; // 转换为实际数字
                            Speed = (num == 0) ? 10 : num; // 处理0的特殊逻辑
                            CfgTimeScale.Value = Speed;
                            //TimeScaleMgr.Get().SetGameTimeScale(speed);
                            //timer.Stop(); // 检测到按键后立即停止计时
                            return;
                        }
                    }
                }

                Thread.Sleep(1); // 优化：降低空循环时的 CPU 占用

            }


            if (inputSystem.GetKeyDown(KeyCode.PageDown,out isKeyDown))
            {
                Speed = Math.Max(1, Speed - 1);
                CfgTimeScale.Value = Speed;
            }

            if (inputSystem.GetKeyDown(KeyCode.PageUp,out isKeyDown))
            {
                Speed = Math.Min(32, Speed + 1);
                CfgTimeScale.Value = Speed;
            }

            if (Math.Abs(Speed - CfgTimeScale.Value) > 0.01f)
            {
                CfgTimeScale.Value = Speed;
            }
            UnityEngine.Time.timeScale = Speed;
            Cursor.visible = true;
        }
    }
}