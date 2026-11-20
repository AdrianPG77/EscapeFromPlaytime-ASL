state("EscapeFromPlaytime-Win64-Shipping") { }

startup
{
    print("[EFP] Script cargado correctamente");
}

init
{
    const long SHOW_FLAG = 0x3E0;

    var module = modules.First();
    if (module.ModuleMemorySize == 0) throw new Exception("modulo no listo");

    long exe = module.BaseAddress.ToInt64();
    long guo = 0;
    long fnp = 0;

    var scanner = new SignatureScanner(game, module.BaseAddress, module.ModuleMemorySize);

    var guoTarget = new SigScanTarget(9, "48 83 EC 20 33 F6 48 8D 05 ?? ?? ?? ?? 48 89 01 45 8B D1 48 89 71 10");
    IntPtr guoRip = scanner.Scan(guoTarget);
    guo = (guoRip != IntPtr.Zero) ? guoRip.ToInt64() + 4 + game.ReadValue<int>(guoRip) : exe + 0xB3991D0;

    var fnpTarget = new SigScanTarget(8, "48 8B D9 74 17 48 8D 05 ?? ?? ?? ?? 48 8B D1 48 8B C8 48 83 C4 20 5B");
    IntPtr fnpRip = scanner.Scan(fnpTarget);
    fnp = (fnpRip != IntPtr.Zero) ? fnpRip.ToInt64() + 4 + game.ReadValue<int>(fnpRip) : exe + 0xB2B5680;

    if (guo == 0 || fnp == 0)
        throw new Exception("[EFP] Error al resolver estructuras del motor.");

    Func<long, long> rl = a => game.ReadValue<long>(new IntPtr(a));
    Func<long, int>  ri = a => game.ReadValue<int>(new IntPtr(a));

    var clock = System.Diagnostics.Stopwatch.StartNew();
    var nameCls = new System.Collections.Generic.Dictionary<int, int>();

    Func<int, int> classify = idx =>
    {
        if (idx < 0) return 0;
        long block = rl(fnp + 0x10 + (long)(idx >> 16) * 8);
        if (block == 0) return 0;

        long e = block + (long)(idx & 0xFFFF) * 2;
        int h = game.ReadValue<ushort>(new IntPtr(e));
        if ((h & 1) == 1) return 0;

        int len = h >> 6;
        if (len != 15 && len != 23) return 0;

        byte[] b = game.ReadBytes(new IntPtr(e + 2), len);
        if (b == null) return 0;

        string s = System.Text.Encoding.ASCII.GetString(b);
        if (s == "WBP_PlayerHUD_C") return 1;
        if (s == "WBP_AfterActionReport_C") return 2;
        return 0;
    };

    var addr = new long[3];
    var slot = new int[3];
    var nidx = new int[3];

    long nextValidate = 0;
    long nextScan = 0;
    bool scanning = false;
    int cursor = 0;
    int endIdx = 0;
    int lastTotal = 0;
    long objsPtr = 0;

    const int CAP = 1048576;
    var prevPtr = new long[CAP];
    var prevSer = new int[CAP];

    Func<int, int, bool> scanRange = (from0, to0) =>
    {
        int pos = from0;
        while (pos < to0)
        {
            int inChunk = pos & 0xFFFF;
            int count = Math.Min(512, Math.Min(to0 - pos, 65536 - inChunk));

            long chunkPtr = rl(objsPtr + (long)(pos >> 16) * 8);
            if (chunkPtr != 0)
            {
                byte[] buf = game.ReadBytes(new IntPtr(chunkPtr + (long)inChunk * 0x18), count * 0x18);
                if (buf != null)
                {
                    for (int j = 0; j < count; j++)
                    {
                        int offset = j * 0x18;
                        long obj = BitConverter.ToInt64(buf, offset);
                        int ser = BitConverter.ToInt32(buf, offset + 0x10);
                        int gi = pos + j;

                        if (gi < CAP)
                        {
                            if (prevPtr[gi] == obj && prevSer[gi] == ser) continue;
                            prevPtr[gi] = obj;
                            prevSer[gi] = ser;
                        }

                        if (obj == 0) continue;

                        long nm = rl(obj + 0x18);
                        if (nm == 0 && gi < CAP) { prevPtr[gi] = 0; prevSer[gi] = 0; continue; }

                        int ci = unchecked((int)(nm & 0xFFFFFFFFL));
                        int num = unchecked((int)(nm >> 32));
                        if (num == 0) continue;

                        int cls;
                        if (!nameCls.TryGetValue(ci, out cls))
                        {
                            cls = classify(ci);
                            nameCls[ci] = cls;
                        }

                        if (cls != 0 && addr[cls] == 0)
                        {
                            addr[cls] = obj;
                            slot[cls] = gi;
                            nidx[cls] = ci;
                        }
                    }
                }
            }
            pos += count;
        }
        return true;
    };

    Func<bool> step = () =>
    {
        long now = clock.ElapsedMilliseconds;

        if (now >= nextValidate)
        {
            nextValidate = now + 1000;
            long arr = rl(guo + 0x10);
            for (int k = 1; k <= 2; k++)
            {
                if (addr[k] == 0) continue;
                long ch = arr == 0 ? 0 : rl(arr + (long)(slot[k] >> 16) * 8);
                long item = ch == 0 ? 0 : rl(ch + (long)(slot[k] & 0xFFFF) * 0x18);
                if (item != addr[k] || ri(addr[k] + 0x18) != nidx[k])
                {
                    addr[k] = 0;
                }
            }
        }

        if (addr[1] != 0 && addr[2] != 0)
        {
            scanning = false;
            return true;
        }

        objsPtr = rl(guo + 0x10);
        int nowTotal = ri(guo + 0x24);
        if (nowTotal <= 0 || nowTotal > 20000000 || objsPtr == 0) return true;

        if (lastTotal > 0 && nowTotal > lastTotal)
        {
            int to2 = Math.Min(nowTotal, lastTotal + 4096);
            scanRange(lastTotal, to2);
            lastTotal = to2;
        }
        else if (nowTotal < lastTotal)
        {
            lastTotal = nowTotal;
        }

        if (!scanning)
        {
            if (now < nextScan) return true;
            cursor = 0;
            endIdx = nowTotal;
            scanning = true;
            if (lastTotal == 0) lastTotal = nowTotal;
        }

        while (cursor < endIdx && clock.ElapsedMilliseconds - now < 3)
        {
            int to1 = Math.Min(endIdx, cursor + 512);
            scanRange(cursor, to1);
            cursor = to1;
        }

        if (cursor >= endIdx)
        {
            scanning = false;
            nextScan = now + 100;
        }
        return true;
    };

    vars.Step = step;
    vars.Shown = (Func<int, bool>)(k => addr[k] != 0 && game.ReadValue<byte>(new IntPtr(addr[k] + SHOW_FLAG)) == 1);

    vars.hud = false;
    vars.hudPrev = false;
    vars.res = false;
    vars.resPrev = false;
}

update
{
    vars.Step();
    vars.hudPrev = vars.hud;
    vars.resPrev = vars.res;
    vars.hud = vars.Shown(1);
    vars.res = vars.Shown(2);
}

start
{
    return !vars.hudPrev && vars.hud;
}

split
{
    return !vars.resPrev && vars.res;
}

isLoading
{
    return !vars.hud || vars.res;
}
