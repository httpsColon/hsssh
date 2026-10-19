#nullable enable
// =============================================================================
//  License Guard · .NET / C# 客户端 SDK
//  =============================================================================
//  适用：WPF / WinForms / .NET 桌面程序、Unity 桌面端、控制台工具
//
//  签名算法用 ECDSA P-256（ES256），因为 .NET 内置支持，无需第三方库。
//  在后台创建产品时把「签名算法」选成 es256 即可。
//
//  用法：
//      var guard = new LicenseGuard(new GuardOptions {
//          ServerUrl  = "https://license-guard.your-name.workers.dev",
//          AppId      = "mytool",
//          PublicKey  = "粘贴 gen-keys 输出的 ES256 公钥 (SPKI base64)",
//          LicenseKey = "ABCD-EFGH-JKMN-PQRS",
//          FailMode   = FailMode.Hard,   // 到期直接闪退
//      });
//
//      guard.Authorize();        // 校验；不通过则终止进程
//      guard.StartWatchdog();    // 运行期看守，到期瞬间退出
//
//      if (guard.HasFeature("pro")) { ... }
// =============================================================================

using System.Collections.Concurrent;
using System.Globalization;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace LicenseGuard;

/// <summary>授权失败时抛出的异常。</summary>
public sealed class LicenseException : Exception
{
    public string Code { get; }
    public LicenseException(string code, string message) : base($"[{code}] {message}") => Code = code;
}

/// <summary>到期时的行为。</summary>
public enum FailMode
{
    /// <summary>不走任何清理流程直接终止进程 —— 表现就是「闪退」。</summary>
    Hard,
    /// <summary>写出提示（可选弹窗）后退出。</summary>
    Message,
}

public sealed class GuardOptions
{
    public string ServerUrl { get; set; } = "";
    public string AppId { get; set; } = "";
    /// <summary>ES256 公钥，SPKI DER 的 base64。</summary>
    public string PublicKey { get; set; } = "";
    public string LicenseKey { get; set; } = "";
    public FailMode FailMode { get; set; } = FailMode.Hard;
    public int ExitCode { get; set; } = 0;

    /// <summary>检测到系统时间被回拨时是否直接判失效。</summary>
    public bool StrictClock { get; set; } = true;
    public int ClockToleranceSeconds { get; set; } = 300;
    public int RequestTimeoutSeconds { get; set; } = 8;
    public int RetryTimes { get; set; } = 3;
    public int HeartbeatSeconds { get; set; } = 21600;
    /// <summary>看门狗检查间隔；到期后最多这么久就会退出。</summary>
    public int WatchdogIntervalSeconds { get; set; } = 120;

    public string? StorageDirectory { get; set; }

    /// <summary>设置后不会自动退出，而是把失败交给你处理。</summary>
    public Action<string, string>? OnDenied { get; set; }

    /// <summary>可选诊断日志回调。</summary>
    public Action<string>? OnLog { get; set; }

    public bool Debug { get; set; }
}

public sealed class LicenseInfo
{
    public string Status { get; set; } = "unknown";
    public string Code { get; set; } = "";
    public string Message { get; set; } = "";
    public string? Customer { get; set; }
    public List<string> Features { get; set; } = new();
    public long? ExpiresAt { get; set; }
    public long? HardExpiresAt { get; set; }
    public int MaxDevices { get; set; } = 1;
    public int Activations { get; set; }
    public long ServerTime { get; set; }
    public bool Offline { get; set; }

    public int? DaysLeft => HardExpiresAt is null
        ? null
        : (int)Math.Floor((HardExpiresAt.Value - DateTimeOffset.UtcNow.ToUnixTimeSeconds()) / 86400.0);

    public DateTime? ExpiresAtLocal => ExpiresAt is null
        ? null
        : DateTimeOffset.FromUnixTimeSeconds(ExpiresAt.Value).ToLocalTime().DateTime;
}

// =============================================================================

public sealed class LicenseGuard
{
    private readonly GuardOptions _o;
    private readonly string _machineId;
    private readonly StateStore _store;
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    private Dictionary<string, JToken> _state = new();
    private LicenseInfo? _info;
    private Timer? _timer;
    private volatile bool _running;

    public LicenseInfo Info => _info ?? throw new LicenseException("NOT_VERIFIED", "尚未执行校验");

    /// <summary>
    /// 运行时可以改配置。典型用法：先用 OnDenied 完成启动期校验，
    /// 再把 OnDenied 换成「运行期到期」的处理逻辑，然后 StartWatchdog()。
    /// </summary>
    public GuardOptions Options => _o;

    public LicenseGuard(GuardOptions options)
    {
        _o = options ?? throw new ArgumentNullException(nameof(options));
        if (string.IsNullOrWhiteSpace(_o.ServerUrl)) throw new ArgumentException("缺少 ServerUrl");
        if (string.IsNullOrWhiteSpace(_o.AppId)) throw new ArgumentException("缺少 AppId");
        if (string.IsNullOrWhiteSpace(_o.PublicKey)) throw new ArgumentException("缺少 PublicKey");

        _o.ServerUrl = _o.ServerUrl.TrimEnd('/');
        _machineId = MachineFingerprint.Compute();
        _store = new StateStore(_o.AppId, _machineId, _o.StorageDirectory);
    }

    private void Log(string msg)
    {
        if (_o.Debug) Console.Error.WriteLine("[license-guard] " + msg);
        try { _o.OnLog?.Invoke(msg); } catch { /* logging must not affect authorization */ }
    }

    // ---------------------------------------------------------------- 终止
    private void Deny(string code, string message)
    {
        if (_o.OnDenied is not null)
        {
            try { _o.OnDenied(code, message); } catch { /* ignore */ }
            throw new LicenseException(code, message);
        }
        Terminate(_o.FailMode, _o.ExitCode, message, code);
        throw new LicenseException(code, message); // 正常情况到不了这里
    }

    private static void Terminate(FailMode mode, int exitCode, string message, string code)
    {
        if (mode == FailMode.Message)
        {
            var line = new string('!', 58);
            try
            {
                Console.Error.WriteLine($"\n{line}\n  {message}\n  (错误代码: {code})\n{line}\n  请联系软件供应商续期。\n");
                Console.Error.Flush();
            }
            catch { /* ignore */ }
        }
        // 不走 finally / Dispose / 事件，直接终止 —— 表现就是「闪退」
        Environment.Exit(exitCode);
    }

    // ------------------------------------------------------------ 网络请求
    private async Task<JObject?> PostAsync(string path, object payload)
    {
        var body = JsonConvert.SerializeObject(payload);
        Exception? last = null;

        for (var attempt = 0; attempt < Math.Max(1, _o.RetryTimes); attempt++)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_o.RequestTimeoutSeconds));
            try
            {
                using var content = new StringContent(body, Encoding.UTF8, "application/json");
                using var resp = await Http.PostAsync(_o.ServerUrl + path, content, cts.Token).ConfigureAwait(false);
                var text = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                var root = JObject.Parse(text);

                var status = (int)resp.StatusCode;
                if (status is 401 or 403 or 404 or 409 or 429) return root;   // 明确拒绝，不重试
                if (resp.IsSuccessStatusCode) return root;
                last = new HttpRequestException($"HTTP {status}");
            }
            catch (Exception ex)
            {
                last = ex;
            }

            if (attempt < _o.RetryTimes - 1)
                await Task.Delay(800 * (attempt + 1)).ConfigureAwait(false);
        }

        Log("网络不可用: " + last?.Message);
        return null;
    }

    // ---------------------------------------------------------------- 校验
    public async Task<LicenseInfo> VerifyAsync(bool allowOffline = true)
    {
        _state = _store.Load();
        if (_state.ContainsKey("__tampered__"))
        {
            _state.Clear();
        }

        var rawKey = ResolveLicenseKey();
        if (string.IsNullOrWhiteSpace(rawKey))
            throw new LicenseException("NO_KEY", "未找到授权码（可传 LicenseKey、设环境变量 LICENSE_KEY 或放 license.key 文件）");

        var (now, tampered) = EffectiveNow();
        if (tampered && _o.StrictClock) Deny("CLOCK_TAMPERED", "检测到系统时间被修改，授权校验失败");

        /* ---- 1) 缓存令牌 → 先尝试离线判定 ---- */
        var cached = _state.TryGetValue("token", out var tEl) ? tEl.ToObject<string>() : null;
        Dictionary<string, JToken>? payload = null;

        if (!string.IsNullOrEmpty(cached))
        {
            try
            {
                payload = Token.Verify(cached!, _o.PublicKey);
            }
            catch (LicenseException ex)
            {
                Log("缓存令牌签名校验失败；保留文件以便诊断，不会使用其中的令牌: " + ex.Code);
                _state.Clear();
                cached = null;
                payload = null;
            }
        }

        if (payload is not null)
        {
            var mid = GetString(payload, "mid");
            if (!string.IsNullOrEmpty(mid) && mid != _machineId)
                Deny("MACHINE_MISMATCH", "该授权绑定了另一台设备");

            var hexp = GetLong(payload, "hexp");
            if (hexp is not null && now > hexp.Value) Deny("LICENSE_EXPIRED", ExpiredMessage(payload));

            var exp = GetLong(payload, "exp") ?? 0;
            if (now <= exp && now <= OfflineUntil())
            {
                _state["last_wall"] = new JValue(now);
                _store.Save(_state);
                _info = FromPayload(payload, true, null);
                return _info;
            }
        }

        /* ---- 2) 联网校验 ---- */
        // The installer owns first-time activation. The BepInEx plugin must only
        // verify that existing activation, or a missing local cache could consume
        // a second device slot when the game starts.
        const string endpoint = "/v1/verify";
        var resp = await PostAsync(endpoint, new
        {
            app_id = _o.AppId,
            key = rawKey,
            machine_id = _machineId,
            machine_name = Environment.MachineName,
            platform = "windows",
            app_version = typeof(LicenseGuard).Assembly.GetName().Version?.ToString() ?? "1.0.0",
        }).ConfigureAwait(false);

        if (resp is null)
        {
            if (payload is not null && allowOffline)
            {
                var until = OfflineUntil();
                if (until > 0 && now > until)
                    Deny("OFFLINE_TOO_LONG", "长时间未联网校验，授权已失效，请连接网络后重试");
                Log("离线放行，容忍截止 " + until);
                _info = FromPayload(payload, true, null);
                return _info;
            }
            throw new LicenseException("NETWORK", "无法连接授权服务器，且本地没有可用的离线授权");
        }

        if (resp["ok"]?.ToObject<bool>() != true)
        {
            var code = resp["code"]?.ToObject<string>() ?? "DENIED";
            var msg = resp["message"]?.ToObject<string>() ?? "授权被拒绝";
            Deny(code!, msg!);
        }

        var data = resp["data"] as JObject ?? new JObject();
        var token = data["token"]?.ToObject<string>()!;
        payload = Token.Verify(token, _o.PublicKey);

        if (GetString(payload, "mid") != _machineId)
            Deny("MACHINE_MISMATCH", "服务端返回的授权与当前设备不匹配");

        (now, tampered) = EffectiveNow();
        if (tampered && _o.StrictClock) Deny("CLOCK_TAMPERED", "检测到系统时间被修改");

        var hardExp = GetLong(payload, "hexp");
        if (hardExp is not null && now > hardExp.Value) Deny("LICENSE_EXPIRED", ExpiredMessage(payload));

        var policy = data["policy"] as JObject;
        var serverTime = data["server_time"]?.ToObject<long>() ?? now;

        _state = new Dictionary<string, JToken>
        {
            ["token"] = new JValue(token),
            ["last_online"] = new JValue(serverTime),
            ["last_wall"] = new JValue(now),
            ["license_key"] = new JValue(rawKey),
            ["offline_grace_days"] = new JValue(PolicyInt(policy, "offline_grace_days", 0)),
            ["heartbeat_sec"] = new JValue(PolicyInt(policy, "heartbeat_sec", _o.HeartbeatSeconds)),
            ["install_id"] = new JValue(Guid.NewGuid().ToString("N")),
        };
        _store.Save(_state);

        var fm = policy?["fail_mode"]?.ToObject<string>();
        if (fm == "hard") _o.FailMode = FailMode.Hard;
        else if (fm == "message") _o.FailMode = FailMode.Message;

        _info = FromPayload(payload, false, data);
        Log($"校验通过: {_info.Status} 到期: {_info.ExpiresAtLocal}");
        return _info;
    }

    /// <summary>启动时调用。不通过则按策略终止进程（Hard = 直接闪退）。</summary>
    public LicenseInfo Authorize()
    {
        try
        {
            return VerifyAsync().GetAwaiter().GetResult();
        }
        catch (LicenseException)
        {
            throw; // Deny() 内部已经处理过退出；只有 OnDenied 模式下才会到这里
        }
    }

    /// <summary>后台看门狗：到期时刻一到，即使程序正在运行也会立刻退出。</summary>
    public void StartWatchdog()
    {
        if (_running) return;
        _running = true;
        var interval = TimeSpan.FromSeconds(Math.Max(15, _o.WatchdogIntervalSeconds));

        _timer = new Timer(async _ =>
        {
            if (!_running) return;
            try
            {
                await VerifyAsync().ConfigureAwait(false);
                var hb = _state.TryGetValue("heartbeat_sec", out var h) ? h.ToObject<int>() : _o.HeartbeatSeconds;
                var next = TimeSpan.FromSeconds(Math.Max(15, Math.Min(900, hb)));
                if (_running) _timer?.Change(next, Timeout.InfiniteTimeSpan);
            }
            catch (LicenseException ex)
            {
                Log("看门狗: 失败 " + ex.Code);
                _running = false;
                if (_o.OnDenied is null) Terminate(_o.FailMode, _o.ExitCode, ex.Message, ex.Code);
            }
        }, null, interval, Timeout.InfiniteTimeSpan);
    }

    public void StopWatchdog()
    {
        _running = false;
        _timer?.Dispose();
        _timer = null;
    }

    public bool HasFeature(string name) => _info?.Features.Contains(name) == true;
    public int? DaysLeft() => _info?.DaysLeft;

    /// <summary>主动解绑当前设备。</summary>
    public async Task<bool> ReleaseAsync()
    {
        var rawKey = ResolveLicenseKey();
        if (string.IsNullOrWhiteSpace(rawKey)) return false;
        var resp = await PostAsync("/v1/deactivate", new
        {
            app_id = _o.AppId,
            key = rawKey,
            machine_id = _machineId,
        }).ConfigureAwait(false);
        if (resp is not null && resp["ok"]?.ToObject<bool>() == true)
        {
            _store.Clear();
            _state.Clear();
            return true;
        }
        return false;
    }

    // ---------------------------------------------------------------- 内部
    private string ResolveLicenseKey()
    {
        if (!string.IsNullOrWhiteSpace(_o.LicenseKey)) return _o.LicenseKey.Trim();

        foreach (var name in new[] { "LICENSE_KEY", _o.AppId.ToUpperInvariant() + "_LICENSE_KEY" })
        {
            var v = Environment.GetEnvironmentVariable(name);
            if (!string.IsNullOrWhiteSpace(v)) return v.Trim();
        }

        var exeDir = AppContext.BaseDirectory;
        foreach (var dir in new[] { exeDir, Directory.GetCurrentDirectory(), _store.Directory })
        {
            var f = Path.Combine(dir, "license.key");
            try
            {
                if (File.Exists(f))
                {
                    var t = File.ReadAllText(f).Trim();
                    if (t.Length > 0) return t.Split('\n')[0].Trim();
                }
            }
            catch { /* ignore */ }
        }
        return "";
    }

    private (long now, bool tampered) EffectiveNow()
    {
        var wall = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var last = _state.TryGetValue("last_wall", out var l) ? l.ToObject<long>() : 0;
        if (last > 0 && wall < last - _o.ClockToleranceSeconds)
        {
            Log($"检测到系统时间回拨: now={wall} last={last}");
            return (last, true);
        }
        return (wall, false);
    }

    private long OfflineUntil()
    {
        var last = _state.TryGetValue("last_online", out var l) ? l.ToObject<long>() : 0;
        if (last == 0) return 0;
        var grace = _state.TryGetValue("offline_grace_days", out var g) ? g.ToObject<int>() : 0;
        return last + grace * 86400L;
    }

    private static string ExpiredMessage(Dictionary<string, JToken> p)
    {
        var aexp = GetLong(p, "aexp");
        return aexp is null
            ? "授权已到期"
            : "授权已于 " + DateTimeOffset.FromUnixTimeSeconds(aexp.Value).ToLocalTime().ToString("yyyy-MM-dd") + " 到期";
    }

    private static int PolicyInt(JObject? policy, string key, int fallback)
        => policy?[key]?.Type == JTokenType.Integer ? policy[key]!.ToObject<int>() : fallback;

    private static LicenseInfo FromPayload(Dictionary<string, JToken> payload, bool offline, JObject? data)
    {
        var info = new LicenseInfo
        {
            Offline = offline,
            Customer = GetString(payload, "cus"),
            ExpiresAt = GetLong(payload, "aexp"),
            HardExpiresAt = GetLong(payload, "hexp"),
            ServerTime = GetLong(payload, "srv") ?? 0,
            Status = "active",
            Code = offline ? "OFFLINE_OK" : "OK",
        };

        if (payload.TryGetValue("feat", out var feat) && feat is JArray features)
            foreach (var f in features)
                if (f.Type == JTokenType.String && f.ToObject<string>() is { } s) info.Features.Add(s);

        if (data is { } d)
        {
            if (d["status"]?.ToObject<string>() == "grace") info.Status = "grace";
            if (d["code"]?.ToObject<string>() is { } c) info.Code = c;
            if (d["message"]?.ToObject<string>() is { } m) info.Message = m;
            if (d["license"] is JObject lic)
            {
                if (lic["max_devices"]?.Type == JTokenType.Integer) info.MaxDevices = lic["max_devices"]!.ToObject<int>();
                if (lic["activations"]?.Type == JTokenType.Integer) info.Activations = lic["activations"]!.ToObject<int>();
            }
        }
        return info;
    }

    private static string? GetString(Dictionary<string, JToken> d, string key)
        => d.TryGetValue(key, out var el) && el.Type == JTokenType.String ? el.ToObject<string>() : null;

    private static long? GetLong(Dictionary<string, JToken> d, string key)
        => d.TryGetValue(key, out var el) && el.Type == JTokenType.Integer ? el.ToObject<long>() : null;
}

// =============================================================================
//  令牌验签
// =============================================================================

internal static class Token
{
    public static Dictionary<string, JToken> Verify(string token, string publicKeySpkiBase64)
    {
        var parts = token.Split('.');
        if (parts.Length != 3) throw new LicenseException("BAD_TOKEN", "令牌格式错误");

        var data = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        var signature = Base64UrlDecode(parts[2]);

        var ok = false;
        try
        {
            var spki = Convert.FromBase64String(publicKeySpkiBase64);
            if (spki.Length < 65 || spki[spki.Length - 65] != 0x04)
                throw new CryptographicException("Expected an uncompressed P-256 public key");
            // Do not use CNG here: the Unity/Mono runtime bundled with Hearthstone
            // can report PlatformNotSupported for CngKey.Import.
            ok = EcdsaP256.Verify(spki, data, signature);
        }
        catch (Exception ex)
        {
            throw new LicenseException("BAD_PUBLIC_KEY", "公钥格式错误: " + ex.Message);
        }

        if (!ok) throw new LicenseException("BAD_SIGNATURE", "授权令牌签名校验失败（文件可能被篡改）");

        var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
        var root = JObject.Parse(payloadJson);
        var dict = root.Properties().ToDictionary(prop => prop.Name, prop => prop.Value);
        return dict;
    }

    private static byte[] Base64UrlDecode(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        switch (t.Length % 4)
        {
            case 2: t += "=="; break;
            case 3: t += "="; break;
        }
        return Convert.FromBase64String(t);
    }
}

/// <summary>Pure managed ES256 verifier for runtimes without CNG ECDSA support.</summary>
internal static class EcdsaP256
{
    private static readonly BigInteger P = FromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    private static readonly BigInteger N = FromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    private static readonly BigInteger B = FromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    private static readonly Point G = new Point(
        FromHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
        FromHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
        BigInteger.One);

    public static bool Verify(byte[] spki, byte[] data, byte[] signature)
    {
        if (signature.Length != 64)
            return false;

        var pointOffset = spki.Length - 65;
        if (spki[pointOffset] != 0x04)
            throw new CryptographicException("Expected an uncompressed P-256 public key");

        var qx = FromUnsignedBigEndian(spki, pointOffset + 1, 32);
        var qy = FromUnsignedBigEndian(spki, pointOffset + 33, 32);
        if (qx >= P || qy >= P || Mod(qy * qy - qx * qx * qx + 3 * qx - B, P) != BigInteger.Zero)
            throw new CryptographicException("Invalid P-256 public point");

        var r = FromUnsignedBigEndian(signature, 0, 32);
        var s = FromUnsignedBigEndian(signature, 32, 32);
        if (r <= BigInteger.Zero || r >= N || s <= BigInteger.Zero || s >= N)
            return false;

        byte[] hash;
        using (var sha = SHA256.Create()) hash = sha.ComputeHash(data);
        var z = Mod(FromUnsignedBigEndian(hash, 0, hash.Length), N);
        var inverseS = BigInteger.ModPow(s, N - 2, N);
        var u1 = Mod(z * inverseS, N);
        var u2 = Mod(r * inverseS, N);

        var q = new Point(qx, qy, BigInteger.One);
        var result = Add(Multiply(u1, G), Multiply(u2, q));
        if (result.Z.IsZero)
            return false;

        var inverseZ = BigInteger.ModPow(result.Z, P - 2, P);
        var inverseZ2 = Mod(inverseZ * inverseZ, P);
        var x = Mod(result.X * inverseZ2, P);
        return Mod(x, N) == r;
    }

    private static Point Multiply(BigInteger scalar, Point point)
    {
        var result = Point.Infinity;
        var addend = point;
        while (scalar > BigInteger.Zero)
        {
            if (!scalar.IsEven) result = Add(result, addend);
            addend = Double(addend);
            scalar >>= 1;
        }
        return result;
    }

    private static Point Double(Point point)
    {
        if (point.Z.IsZero || point.Y.IsZero) return Point.Infinity;

        var delta = Mod(point.Z * point.Z, P);
        var gamma = Mod(point.Y * point.Y, P);
        var beta = Mod(point.X * gamma, P);
        var alpha = Mod(3 * (point.X - delta) * (point.X + delta), P);
        var x = Mod(alpha * alpha - 8 * beta, P);
        var z = Mod((point.Y + point.Z) * (point.Y + point.Z) - gamma - delta, P);
        var y = Mod(alpha * (4 * beta - x) - 8 * gamma * gamma, P);
        return new Point(x, y, z);
    }

    private static Point Add(Point left, Point right)
    {
        if (left.Z.IsZero) return right;
        if (right.Z.IsZero) return left;

        var z1z1 = Mod(left.Z * left.Z, P);
        var z2z2 = Mod(right.Z * right.Z, P);
        var u1 = Mod(left.X * z2z2, P);
        var u2 = Mod(right.X * z1z1, P);
        var s1 = Mod(left.Y * right.Z * z2z2, P);
        var s2 = Mod(right.Y * left.Z * z1z1, P);
        if (u1 == u2)
            return s1 == s2 ? Double(left) : Point.Infinity;

        var h = Mod(u2 - u1, P);
        var i = Mod(4 * h * h, P);
        var j = Mod(h * i, P);
        var rr = Mod(2 * (s2 - s1), P);
        var v = Mod(u1 * i, P);
        var x = Mod(rr * rr - j - 2 * v, P);
        var y = Mod(rr * (v - x) - 2 * s1 * j, P);
        var z = Mod(((left.Z + right.Z) * (left.Z + right.Z) - z1z1 - z2z2) * h, P);
        return new Point(x, y, z);
    }

    private static BigInteger Mod(BigInteger value, BigInteger modulus)
    {
        var result = value % modulus;
        return result.Sign < 0 ? result + modulus : result;
    }

    private static BigInteger FromUnsignedBigEndian(byte[] bytes, int offset, int count)
    {
        var littleEndian = new byte[count + 1];
        for (var i = 0; i < count; i++) littleEndian[i] = bytes[offset + count - 1 - i];
        return new BigInteger(littleEndian);
    }

    private static BigInteger FromHex(string value)
    {
        var bytes = new byte[value.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(value.Substring(i * 2, 2), 16);
        return FromUnsignedBigEndian(bytes, 0, bytes.Length);
    }

    private sealed class Point
    {
        public static readonly Point Infinity = new Point(BigInteger.Zero, BigInteger.One, BigInteger.Zero);
        public readonly BigInteger X;
        public readonly BigInteger Y;
        public readonly BigInteger Z;
        public Point(BigInteger x, BigInteger y, BigInteger z) { X = x; Y = y; Z = z; }
    }
}

// =============================================================================
//  硬件指纹
// =============================================================================

internal static class MachineFingerprint
{
    private static string? _cached;

    public static string Compute()
    {
        if (_cached is not null) return _cached;

        string? identity = null;

        // 仅用 Windows MachineGuid 作为主标识，避免 .NET Framework 与 Unity/Mono
        // 返回不同的 Environment.OSVersion 字符串，导致同一台电脑算出不同 ID。
        try
        {
            using var baseKey = Microsoft.Win32.RegistryKey.OpenBaseKey(
                Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", false);
            if (key?.GetValue("MachineGuid") is string guid && guid.Length > 0)
                identity = "machine-guid:" + guid.Trim().ToLowerInvariant();
        }
        catch { /* 非 Windows 或权限不足时使用下方回退值 */ }

        if (identity is null)
        {
            var sb = new StringBuilder();
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"HARDWARE\DESCRIPTION\System\BIOS", false);
                if (key?.GetValue("SystemProductName") is string p) sb.Append("prod:").Append(p).Append('|');
                if (key?.GetValue("BaseBoardProduct") is string b) sb.Append("board:").Append(b).Append('|');
            }
            catch { /* ignore */ }

            sb.Append("host:").Append(Environment.MachineName);
            identity = sb.ToString();
        }

        byte[] hash;
        using (var sha = SHA256.Create()) hash = sha.ComputeHash(Encoding.UTF8.GetBytes(identity));
        _cached = FrameworkCompat.ToHex(hash).Substring(0, 32);
        return _cached;
    }
}

// =============================================================================
//  本地状态存储（HMAC 完整性保护）
// =============================================================================

internal sealed class StateStore
{
    private const string Magic = "LGST1";
    private readonly byte[] _key;

    public string Directory { get; }
    private string Path => System.IO.Path.Combine(Directory, "state.dat");

    public StateStore(string appId, string machineId, string? directory)
    {
        Directory = directory ?? DefaultDir(appId);
        using (var sha = SHA256.Create()) _key = sha.ComputeHash(Encoding.UTF8.GetBytes($"license-guard::{appId}::{machineId}"));
    }

    private static string DefaultDir(string appId)
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(root)) root = System.IO.Path.GetTempPath();
        return System.IO.Path.Combine(root, appId);
    }

    private byte[] Mac(byte[] body) { using (var h = new HMACSHA256(_key)) return h.ComputeHash(body); }

    public Dictionary<string, JToken> Load()
    {
        try
        {
            var raw = File.ReadAllBytes(Path);
            var nl = Array.IndexOf(raw, (byte)'\n');
            if (nl < 0) return new();

            var head = Encoding.ASCII.GetString(raw, 0, nl);
            var body = new byte[raw.Length - nl - 1];
            Buffer.BlockCopy(raw, nl + 1, body, 0, body.Length);
            var sep = head.IndexOf(':');
            if (sep < 0) return new();

            if (head.Substring(0, sep) != Magic) return new();

            var expected = FrameworkCompat.ToHex(Mac(body));
            var actual = head.Substring(sep + 1);
            if (expected.Length != actual.Length ||
                !FrameworkCompat.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(actual)))
            {
                return new() { ["__tampered__"] = new JValue(true) };
            }

            var root = JObject.Parse(Encoding.UTF8.GetString(body));
            var dict = root.Properties().ToDictionary(p => p.Name, p => p.Value);
            return dict;
        }
        catch
        {
            return new();
        }
    }

    public void Save(Dictionary<string, JToken> data)
    {
        try
        {
            var body = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(data));
            var head = Encoding.ASCII.GetBytes($"{Magic}:{FrameworkCompat.ToHex(Mac(body))}\n");
            System.IO.Directory.CreateDirectory(Directory);

            var tmp = Path + ".tmp";
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                fs.Write(head, 0, head.Length);
                fs.Write(body, 0, body.Length);
            }
            if (File.Exists(Path)) File.Delete(Path);
            File.Move(tmp, Path);
        }
        catch { /* 磁盘只读时静默降级 */ }
    }

    public void Clear()
    {
        try { if (File.Exists(Path)) File.Delete(Path); } catch { /* ignore */ }
    }
}

internal static class FrameworkCompat
{
    public static string ToHex(byte[] bytes)
    {
        var chars = new char[bytes.Length * 2];
        const string alphabet = "0123456789abcdef";
        for (var i = 0; i < bytes.Length; i++)
        {
            chars[i * 2] = alphabet[bytes[i] >> 4];
            chars[i * 2 + 1] = alphabet[bytes[i] & 0x0f];
        }
        return new string(chars);
    }

    public static bool FixedTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        var diff = 0;
        for (var i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}

